#include <algorithm>
#include <iterator>
#include <random>
#include <cstdlib>

#include "cache.h"
#include "util.h"

#define BTP_NUMBER 8

void CACHE::initialize_replacement() {
}

// find replacement victim
uint32_t CACHE::find_victim(uint32_t cpu, uint64_t instr_id, uint32_t set, const BLOCK* current_set, uint64_t ip, uint64_t full_addr, uint32_t type)
{
    return std::distance(current_set, std::max_element(current_set, std::next(current_set, NUM_WAY), lru_comparator<BLOCK, BLOCK>()));
}

// called on every cache hit and cache fill
void CACHE::update_replacement_state(uint32_t cpu, uint32_t set, uint32_t way, uint64_t full_addr, uint64_t ip, uint64_t victim_addr, uint32_t type,
uint8_t hit)
{
    if (hit && type == WRITEBACK)
        return;

    auto begin = std::next(block.begin(), set * NUM_WAY);
    auto end = std::next(begin, NUM_WAY);
    uint32_t hit_lru = std::next(begin, way)->lru;

    if(hit){
        std::for_each(begin, end, [hit_lru](BLOCK& x) {
            if (x.lru <= hit_lru){
                x.lru++;
            } 
        });
        std::next(begin, way)->lru = 0; // promote to the MRU position
    }else{
        // miss
        int rand_num = static_cast<int>(std::rand() / (RAND_MAX / 100.0)) + 1; // generate a number between 1 to 100
        if(rand_num > BTP_NUMBER){
            std::for_each(begin, end, [hit_lru](BLOCK& x) {
                if (x.lru <= hit_lru){
                    x.lru++;
                } 
            });
            std::next(begin, way)->lru = 0; // promote to the MRU position
        }else{
            std::for_each(begin, end, [hit_lru](BLOCK& x) {
                if (x.lru >= hit_lru){
                    x.lru --;
                } 
            });
            std::next(begin, way)->lru = NUM_WAY - 1; // promote to the LRU position
        }
    }
}

void CACHE::replacement_final_stats() {}
