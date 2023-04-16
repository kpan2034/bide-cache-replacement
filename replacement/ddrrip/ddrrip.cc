#include <algorithm>
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

std::map<CACHE *, unsigned> rrpv_bip_counter;
std::map<CACHE *, std::vector<std::size_t>> rand_sets;
std::map<std::pair<CACHE *, std::size_t>, unsigned> PSEL;
std::map<CACHE *, uint64_t> bip_rand_counter;
std::map<CACHE *, uint64_t> bip_rand_seed;

void CACHE::initialize_replacement() {
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
  // first update RRPV value
  block[set * NUM_WAY + way].lru = maxRRPV;

  auto begin = std::next(block.begin(), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);
  uint64_t hit_lru = std::next(begin, way)->lru;

  rrpv_bip_counter[this]++;
  if (rrpv_bip_counter[this] == BIP_MAX)
    rrpv_bip_counter[this] = 0;
  if (rrpv_bip_counter[this] == 0)
    block[set * NUM_WAY + way].lru = maxRRPV - 1;

  // also update LRU value
  uint64_t val = (bip_rand_seed[this] / 65536) % 100;
  bip_rand_seed[this] = bip_rand_seed[this] * 1103515245 + 12345;
  if(val > BTP_NUMBER) {
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

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set,
                            const BLOCK *current_set, uint64_t ip,
                            uint64_t full_addr, uint32_t type) {
  // figure out if this set is a leader or follower set
  auto begin =
      std::next(std::begin(rand_sets[this]), cpu * NUM_POLICY * SDM_SIZE);
  auto end = std::next(begin, NUM_POLICY * SDM_SIZE);
  auto leader = std::find(begin, end, set);

  if (leader == end) // follower sets
  {
    if (PSEL[std::make_pair(this, cpu)] > PSEL_THRS) // follow DDRIP
    {
      // find maxRRPV line and evict
      // look for the maxRRPV line
      auto begin = std::next(std::begin(block), set * NUM_WAY);
      auto end = std::next(begin, NUM_WAY);
      auto victim =
          std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
      while (victim == end) {
        for (auto it = begin; it != end; ++it)
          it->rrpv++;

        victim =
            std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
      }

      return std::distance(begin, victim);
    } else // follow BIP
    {
      // find LRU line and evict
      return std::distance(current_set,
                           std::max_element(current_set,
                                            std::next(current_set, NUM_WAY),
                                            lru_comparator<BLOCK, BLOCK>()));
    }
  } else if ((leader - begin) % 2 == 0) // even index sets follow DRRIP
  {
    // find maxRRPV line and evict
    // look for the maxRRPV line
    auto begin = std::next(std::begin(block), set * NUM_WAY);
    auto end = std::next(begin, NUM_WAY);
    auto victim =
        std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
    while (victim == end) {
      for (auto it = begin; it != end; ++it)
        it->rrpv++;

      victim =
          std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
    }

    return std::distance(begin, victim);
  } else if ((leader - begin) % 2 == 1) // odd index sets follow BIP
  {
    // find LRU line and evict
    return std::distance(current_set,
                         std::max_element(current_set,
                                          std::next(current_set, NUM_WAY),
                                          lru_comparator<BLOCK, BLOCK>()));
  }
}

// use this function to print out your own stats at the end of simulation
void CACHE::replacement_final_stats() {}
