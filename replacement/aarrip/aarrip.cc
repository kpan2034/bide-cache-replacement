#include "cache.h"

#define maxRRPV 3

// initialize replacement state
void CACHE::initialize_replacement() {
  for (auto &blk : block)
    blk.lru = maxRRPV;
}

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set,
                            const BLOCK *current_set, uint64_t ip,
                            uint64_t full_addr, uint32_t type) {

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
    return x.lru == maxRRPV && x.cpu == cpu;
  }); // hijack the lru field
  if (victim == end) {
    victim = std::find_if(begin, end, [](BLOCK x) { return x.lru == maxRRPV; });
  }

  while (victim == end) {
    std::for_each(begin, end, [cpu](BLOCK &x) {
      if (x.cpu == cpu) {
        x.lru++;
      }
    });

    victim = std::find_if(begin, end, [](BLOCK x) { return x.lru == maxRRPV; });
  }

  return std::distance(begin, victim);
}

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way,
                                     uint64_t full_addr, uint64_t ip,
                                     uint64_t victim_addr, uint32_t type,
                                     uint8_t hit) {
  if (hit)
    block[set * NUM_WAY + way].lru = 0;
  else
    block[set * NUM_WAY + way].lru = maxRRPV - 1;
}

// use this function to print out your own stats at the end of simulation
void CACHE::replacement_final_stats() {}
