#include <algorithm>
#include <cstdlib>
#include <iterator>
#include <map>
#include <random>

#include "cache.h"
#include "util.h"

#define BTP_NUMBER 8
#define EBIS_SIZE 128

std::map<CACHE *, uint64_t> bip_rand_seed;

struct ebis_entry_t {
  uint32_t cpu;
  uint32_t set;
  uint64_t full_addr;
};

struct stat_entry_t {
  uint64_t ebis_hits;
  std::map<uint32_t, uint64_t> ebis_evictions_per_app;
  std::map<uint32_t, uint64_t> ebis_hits_per_app;
};

std::map<CACHE *, stat_entry_t> stats;

std::map<CACHE *, std::deque<ebis_entry_t>> ebis;

std::map<CACHE *, uint32_t> app_to_evict;

void CACHE::initialize_replacement() {
  bip_rand_seed[this] = 1103515245 + 12345;
  ebis[this] = std::deque<ebis_entry_t>(EBIS_SIZE);
  stats[this] = stat_entry_t{0};
  app_to_evict[this] = 0;
}

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set,
                            const BLOCK *current_set, uint64_t ip,
                            uint64_t full_addr, uint32_t type) {
  uint32_t way = std::distance(
      current_set,
      std::max_element(current_set, std::next(current_set, NUM_WAY),
                       lru_comparator<BLOCK, BLOCK>()));

  // update EbIS
  // Note that even though bip is NOT application aware, the ebis is
  // if EbIS is full, evict a block
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

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way,
                                     uint64_t full_addr, uint64_t ip,
                                     uint64_t victim_addr, uint32_t type,
                                     uint8_t hit) {
  if (hit && type == WRITEBACK)
    return;

  auto begin = std::next(block.begin(), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);
  uint32_t hit_lru = std::next(begin, way)->lru;

  if (hit) {
    std::for_each(begin, end, [hit_lru](BLOCK &x) {
      if (x.lru <= hit_lru) {
        x.lru++;
      }
    });
    std::next(begin, way)->lru = 0; // promote to the MRU position
    return;
  }
  // miss
  // Check if incoming block is in EbIS
  auto ebisBegin = std::begin(ebis[this]);
  auto ebisEnd = std::next(ebisBegin, EBIS_SIZE);
  auto loc = std::find_if(ebisBegin, ebisEnd, [set, full_addr](ebis_entry_t x) {
    return x.set == set && x.full_addr == full_addr;
  });

  if (loc != ebisEnd) { // found in EbIS, put in MRU position always
    stats[this].ebis_hits++;
    stats[this].ebis_hits_per_app[cpu]++;
    std::for_each(begin, end, [hit_lru](BLOCK &x) {
      if (x.lru <= hit_lru) {
        x.lru++;
      }
    });
    std::next(begin, way)->lru = 0; // promote to the MRU position
    return;
  }

  // generate a number between 1 to 100
  uint32_t val = (bip_rand_seed[this] / 65536) % 100;
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

void CACHE::replacement_final_stats() {
  std::cout << "EbIS stats for " << NAME << std::endl;
  std::cout << "Total number of EbIS hits: " << stats[this].ebis_hits
            << std::endl;
  for (uint32_t i = 0; i < NUM_CPUS; i++)
    std::cout << "Total number of EbIS evictions for cpu" << i << ": "
              << stats[this].ebis_evictions_per_app[i] << std::endl;
  for (uint32_t i = 0; i < NUM_CPUS; i++)
    std::cout << "Total number of EbIS hits for cpu" << i << ": "
              << stats[this].ebis_hits_per_app[i] << std::endl;
}
