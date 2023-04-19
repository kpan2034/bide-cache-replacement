#include "cache.h"

#include <algorithm>
#include <cstdio>
#include <deque>
#include <exception>
#include <iterator>
#include <map>

#define maxRRPV 3

#define EBIS_SIZE 128

/* Things to store in EbIS
 * - block metadata: set, tag, application number (cpu)
 */

/* To evict something from EbIS:
 * - for each application, 1)find the closest block 2) find total number of
blocks
* - the one with max difference of these two values is the target application
* - remove first block of the target application
* - insert new block at the head of ebis
*/
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

// initialize replacement state
void CACHE::initialize_replacement() {
  for (auto &blk : block)
    blk.rrpv = maxRRPV;
  ebis[this] = std::deque<ebis_entry_t>(EBIS_SIZE);
  stats[this] = stat_entry_t{0, 0, 0};
  app_to_evict[this] = 0;
}

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set,
                            const BLOCK *current_set, uint64_t ip,
                            uint64_t full_addr, uint32_t type) {
  std::cout << "find_victim" << std::endl;

  /*
   * First look for the maxRRPV line
   * If it exists, then check if the maxRRPV line has blocks of the same
   * application If yes, then select as victim Else, select any other block as
   * victim If no maxRRPV line exists, then increment the RRPV values of blocks
   * of the same application and repeat the above steps
   * */

  // look for the maxRRPV line
  auto begin = std::next(std::begin(block), set * NUM_WAY);
  auto end = std::next(begin, NUM_WAY);
  auto victim = std::find_if(begin, end, [cpu](BLOCK x) {
    return x.rrpv == maxRRPV && x.cpu == cpu;
  }); // hijack the lru field
  if (victim != end) {
    stats[this].num_max_rrpv_same++;
  }
  uint32_t way;

  // if not found, select maxRRPV line of any application
  if (victim == end) {
    victim =
        std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
  }
  if (victim != end) {
    stats[this].num_max_rrpv_other++;
  } else {
    stats[this].num_diff_rrpv_same++;
  }

  uint32_t ct = 0;
  // check if this application has any blocks in this set
  std::for_each(begin, end, [&ct, cpu](BLOCK &x) {
    if (x.cpu == cpu) {
      ct++;
    }
  });

  if (ct > 0) {
    std::cout << "non-zero count" << std::endl;
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
    std::cout << "victim found: " << way << std::endl;
  } else {
    std::cout << "zero count" << std::endl;
    // decay rrpv of everything
    // if not found, increment the RRPV values of blocks of the same
    // application
    while (victim == end) {
      std::for_each(begin, end, [](BLOCK &x) { x.rrpv++; });

      victim =
          std::find_if(begin, end, [](BLOCK x) { return x.rrpv == maxRRPV; });
    }

    way = std::distance(begin, victim);
    std::cout << "victim found: " << way << std::endl;
  }

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

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way,
                                     uint64_t full_addr, uint64_t ip,
                                     uint64_t victim_addr, uint32_t type,
                                     uint8_t hit) {
  // do not update replacement state for writebacks
  if (type == WRITEBACK) {
    block[set * NUM_WAY + way].rrpv = maxRRPV - 1;
    return;
  }

  if (hit) {
    block[set * NUM_WAY + way].rrpv = 0;
    return;
  }
  // miss
  // Check if the incoming block is in EbIS here by comparing the set and the
  // tag
  auto begin = std::begin(ebis[this]);
  auto end = std::next(begin, EBIS_SIZE);
  auto loc = std::find_if(begin, end, [set, full_addr](ebis_entry_t x) {
    return x.set == set && x.full_addr == full_addr;
  });
  if (loc == end) { // not found in EbIS
    block[set * NUM_WAY + way].rrpv = maxRRPV - 1;
    return;
  }
  block[set * NUM_WAY + way].rrpv = 0;
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
