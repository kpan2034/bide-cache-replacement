#include <algorithm>
#include <cstdio>
#include <deque>
#include <exception>
#include <iterator>
#include <map>
#include <utility>

#include "cache.h"

#define BTP_NUMBER 8
#define maxRRPV 3
#define maxLRU NUM_WAY - 1
#define NUM_POLICY 2
#define SDM_SIZE 32
#define TOTAL_SDM_SETS NUM_CPUS *NUM_POLICY *SDM_SIZE
#define BIP_MAX 32
#define PSEL_WIDTH 10
#define PSEL_MAX ((1 << PSEL_WIDTH) - 1)
#define PSEL_THRS PSEL_MAX / 2
#define EBIS_SIZE 128

struct ebis_entry_t {
  uint32_t cpu;
  uint32_t set;
  uint64_t full_addr;
};

struct stat_entry_t {
  uint64_t num_max_rrpv_same;
  uint64_t num_max_rrpv_other;
  uint64_t num_diff_rrpv_same;
  std::map<uint32_t, uint64_t> ebis_evictions_per_app;
};

std::map<CACHE *, stat_entry_t> stats;

std::map<CACHE *, std::deque<ebis_entry_t>> ebis;

std::map<CACHE *, uint32_t> app_to_evict;

std::map<CACHE *, unsigned> rrpv_bip_counter;
std::map<CACHE *, std::vector<std::size_t>> rand_sets;
std::map<std::pair<CACHE *, std::size_t>, unsigned> PSEL;
std::map<CACHE *, uint64_t> bip_rand_counter;
std::map<CACHE *, uint64_t> bip_rand_seed;

void CACHE::initialize_replacement() {
  for (auto &blk : block)
    blk.rrpv = maxRRPV;
  // randomly selected sampler sets
  std::size_t rand_seed = 1103515245 + 12345;
  for (std::size_t i = 0; i < TOTAL_SDM_SETS; i++) {
    std::size_t val = (rand_seed / 65536) % NUM_SET;
    auto loc = std::lower_bound(std::begin(rand_sets[this]),
                                std::end(rand_sets[this]), val);

    while (loc != std::end(rand_sets[this]) && *loc == val) {
      rand_seed = rand_seed * 1103515245 + 12345;
      val = (rand_seed / 65536) % NUM_SET;
      loc = std::lower_bound(std::begin(rand_sets[this]),
                             std::end(rand_sets[this]), val);
    }

    rand_sets[this].insert(loc, val);
  }
  bip_rand_counter[this] = 1103515245 + 12345;
  ebis[this] = std::deque<ebis_entry_t>(EBIS_SIZE);
  stats[this] = stat_entry_t{0, 0, 0};
  app_to_evict[this] = 0;
  // std::cout << "Initialized AADDRRIP" << std::endl;
}

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way,
                                     uint64_t full_addr, uint64_t ip,
                                     uint64_t victim_addr, uint32_t type,
                                     uint8_t hit) {
  // do not update replacement state for writebacks
  if (type == WRITEBACK) {
    block[set * NUM_WAY + way].rrpv = maxRRPV - 1;
    // Don't update LRU for writebacks!
    return;
  }

  // cache hit
  if (hit) {
    // update RRPV
    block[set * NUM_WAY + way].rrpv = 0; // for cache hit, DRRIP always promotes
                                         // a cache line to the MRU position
    // update LRU
    auto begin = std::next(block.begin(), set * NUM_WAY);
    auto end = std::next(begin, NUM_WAY);
    uint64_t hit_lru = std::next(begin, way)->lru;
    std::for_each(begin, end, [hit_lru](BLOCK &x) {
      if (x.lru <= hit_lru)
        x.lru++;
    });
    std::next(begin, way)->lru = 0; // promote to the MRU position
                                    // for cache hit, BIP always promotes
                                    // a cache line to the MRU position
    return;
  }

  // cache miss
  // Find if the element is in the EBIS
  auto ebisBegin = std::begin(ebis[this]);
  auto ebisEnd = std::next(ebisBegin, EBIS_SIZE);
  auto loc = std::find_if(ebisBegin, ebisEnd, [full_addr](ebis_entry_t x) {
    return x.full_addr == full_addr;
  });

  bool inEbis = (loc != ebisEnd);

  // Get iterators to this cache set
  auto begin = std::next(block.begin(), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);

  // first update RRPV value
  if (inEbis) {
    block[set * NUM_WAY + way].rrpv = 0;
  } else {
    // Since it's not in the EbIS, use a bimodal policy to update RRPV
    block[set * NUM_WAY + way].rrpv = maxRRPV;

    rrpv_bip_counter[this]++;
    if (rrpv_bip_counter[this] == BIP_MAX)
      rrpv_bip_counter[this] = 0;
    if (rrpv_bip_counter[this] == 0)
      block[set * NUM_WAY + way].rrpv = maxRRPV - 1;
  }

  // Update LRU value
  uint64_t hit_lru = std::next(begin, way)->lru;
  if (inEbis) {
    // if the value was in the EbIS, place it at the MRU position
    std::for_each(begin, end, [hit_lru](BLOCK &x) {
      if (x.lru <= hit_lru) {
        x.lru++;
      }
    });
    std::next(begin, way)->lru = 0; // promote to the MRU position
  } else {
    uint64_t val = (bip_rand_seed[this] / 65536) % 100;
    bip_rand_seed[this] = bip_rand_seed[this] * 1103515245 + 12345;
    if (val > BTP_NUMBER) {
      std::for_each(begin, end, [hit_lru](BLOCK &x) {
        if (x.lru <= hit_lru) {
          x.lru++;
        }
      });
      std::next(begin, way)->lru = 0; // promote to the MRU position
    } else {
      std::for_each(begin, end, [hit_lru](BLOCK &x) {
        if (x.lru >= hit_lru) {
          x.lru--;
        }
      });
      std::next(begin, way)->lru = NUM_WAY - 1; // demote to the LRU position
    }
  }
}

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set,
                            const BLOCK *current_set, uint64_t ip,
                            uint64_t full_addr, uint32_t type) {
  // figure out if this set is a leader or follower set
  auto setBegin =
      std::next(std::begin(rand_sets[this]), cpu * NUM_POLICY * SDM_SIZE);
  auto setEnd = std::next(setBegin, NUM_POLICY * SDM_SIZE);
  auto leader = std::find(setBegin, setEnd, set);

  uint32_t way;

  if (leader == setEnd) // follower sets
  {
    if (PSEL[std::make_pair(this, cpu)] > PSEL_THRS) // follow DDRIP
    {
      // find maxRRPV line and evict
      // look for the maxRRPV line of this application
      auto begin = std::next(std::begin(block), set * NUM_WAY);
      auto end = std::next(begin, NUM_WAY);
      auto victim = std::find_if(begin, end, [cpu](BLOCK x) {
        return x.rrpv == maxRRPV && x.cpu == cpu;
      });

      // if not found, select maxRRPV line of any application
      if (victim == end) {
        victim =
            std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
      }

      uint32_t ct = 0;
      // check if this application has any blocks in this set
      std::for_each(begin, end, [&ct, cpu](BLOCK &x) {
        if (x.cpu == cpu) {
          ct++;
        }
      });

      if (ct > 0) {
        // if not found, increment the RRPV values of blocks of the same
        // application
        while (victim == end) {
          std::for_each(begin, end, [cpu](BLOCK &x) {
            if (x.cpu == cpu) {
              x.rrpv++;
            }
          });

          victim = std::find_if(begin, end,
                                [](BLOCK x) { return x.rrpv == maxRRPV; });
        }

        way = std::distance(begin, victim);
      } else {
        // decay rrpv of everything
        // if not found, increment the RRPV values of blocks of the same
        // application
        while (victim == end) {
          std::for_each(begin, end, [](BLOCK &x) { x.rrpv++; });

          victim = std::find_if(begin, end,
                                [](BLOCK x) { return x.rrpv == maxRRPV; });
        }

        way = std::distance(begin, victim);
      }
    } else // follow BIP
    {
      // find LRU line and evict
      way = std::distance(current_set,
                          std::max_element(current_set,
                                           std::next(current_set, NUM_WAY),
                                           lru_comparator<BLOCK, BLOCK>()));
    }
  } else if ((leader - setBegin) % 2 == 0) // even index sets follow DRRIP
  {
    // UPDATE PSEL
    if (PSEL[std::make_pair(this, cpu)] > 0)
      PSEL[std::make_pair(this, cpu)]--;
    // find maxRRPV line and evict
    // look for the maxRRPV line
    auto begin = std::next(std::begin(block), set * NUM_WAY);
    auto end = std::next(begin, NUM_WAY);
    auto victim = std::find_if(begin, end, [cpu](BLOCK x) {
      return x.rrpv == maxRRPV && x.cpu == cpu;
    }); // hijack the lru field

    // if not found, select maxRRPV line of any application
    if (victim == end) {
      victim =
          std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
    }

    uint32_t ct = 0;
    // check if this application has any blocks in this set
    std::for_each(begin, end, [&ct, cpu](BLOCK &x) {
      if (x.cpu == cpu) {
        ct++;
      }
    });

    if (ct > 0) {
      // if not found, increment the RRPV values of blocks of the same
      // application
      while (victim == end) {
        std::for_each(begin, end, [cpu](BLOCK &x) {
          if (x.cpu == cpu) {
            x.rrpv++;
          }
        });

        victim =
            std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
      }

      way = std::distance(begin, victim);
    } else {
      // decay rrpv of everything
      // if not found, increment the RRPV values of blocks of the same
      // application
      while (victim == end) {
        std::for_each(begin, end, [cpu](BLOCK &x) { x.rrpv++; });

        victim =
            std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
      }

      way = std::distance(begin, victim);
    }
  } else if ((leader - setBegin) % 2 == 1) // odd index sets follow BIP
  {
    if (PSEL[std::make_pair(this, cpu)] < PSEL_MAX)
      PSEL[std::make_pair(this, cpu)]++;
    // find LRU line and evict
    way = std::distance(current_set,
                        std::max_element(current_set,
                                         std::next(current_set, NUM_WAY),
                                         lru_comparator<BLOCK, BLOCK>()));
  }

  // Update EbIS:

  // If the EbIS is full, then evict a block
  if (ebis[this].size() == EBIS_SIZE) {

    // Figure out target application
    uint32_t victim_cpu = app_to_evict[this] % NUM_CPUS;
    app_to_evict[this] = (app_to_evict[this] + 1) % NUM_CPUS;

    uint32_t target = 0;
    // for each application, 1)find the closest block 2) find total number of
    // blocks
    auto ebisBegin = std::begin(ebis[this]);
    auto ebisEnd = std::next(ebisBegin, EBIS_SIZE);
    for (uint32_t id = 0; id < NUM_CPUS; id++) {
      auto loc = std::find_if(ebisBegin, ebisEnd,
                              [id](ebis_entry_t x) { return x.cpu == id; });
      uint32_t minDistance = std::distance(ebisBegin, loc);
      uint32_t numBlocks = 0;
      for (auto &it : ebis[this]) {
        if (it.cpu == id)
          numBlocks++;
      }

      uint32_t curr_target = numBlocks - minDistance;
      if (numBlocks > minDistance && curr_target > target) {
        victim_cpu = id;
        target = curr_target;
      }
    }

    // Get iterator to this block
    auto loc = std::find_if(ebisBegin, ebisEnd, [victim_cpu](ebis_entry_t x) {
      return x.cpu == victim_cpu;
    });
    stats[this].ebis_evictions_per_app[(*loc).cpu]++;

    // Remove the block
    ebis[this].erase(loc);
  }
  ebis[this].push_back({cpu, set, full_addr});
  return way;
}

// use this function to print out your own stats at the end of simulation
void CACHE::replacement_final_stats() {
  std::cout << "EbIS stats for " << NAME << std::endl;
  std::cout << "Total number of max RRPV lines of same app: "
            << stats[this].num_max_rrpv_same << std::endl;
  std::cout << "Total number of max RRPV lines of other app: "
            << stats[this].num_max_rrpv_other << std::endl;
  std::cout << "Total number of different RRPV lines of same app: "
            << stats[this].num_diff_rrpv_same << std::endl;
  for (uint32_t i = 0; i < NUM_CPUS; i++)
    std::cout << "Total number of EbIS evictions for cpu" << i << ": "
              << stats[this].ebis_evictions_per_app[i] << std::endl;
}
