#!/bin/bash

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <warmup instructions> <simulation instructions> <input trace directory without endslash> <output directory without endslash>"
    echo "Example: ./runit.sh 1000 2000 traces output"
    echo "where: traces and output are folder names."
    exit 1
fi

if [ ! -d "$4" ]; then
    echo "Error: Output directory does not exist."
    exit 1
fi

if [ ! -w "$4" ]; then
    echo "Error: Output directory is not writable."
    exit 1
fi

all_traces=("milc.xz" "namd.xz" "leslie3d.xz" "povray.xz" "soplex.xz" "hmmer.xz" "omnetpp.xz" "sphinx3.xz")
output_dir=$4

warmup_instructions=$1
simulation_instructions=$2

for batch_size in 1 2 4 8; do
    echo "Configuring Batch: $batch_size"        
    # Build the simulator
    ./config.sh champsim_config_$batch_size.json

    echo "Building Batch: $batch_size"        
    make
    
    # Run the simulator with batches of traces
    traces=("${all_traces[@]}")
    while [ ${#traces[@]} -ge $batch_size ]; do
        batch=("${traces[@]:0:$batch_size}")
        traces=("${traces[@]:$batch_size}")
        echo "Running batch: ${batch[@]}"
        output_file="$output_dir/$(echo "${batch[@]}" | sed 's/ /_/g')_$batch_size.txt"
        echo "" > "$output_file"
        for (( i=0; i<${#batch[@]}; i++ )); do
            batch[$i]="$3/${batch[$i]}"
        done
        echo "--warmup_instructions  --simulation_instructions input file = ${batch[@]}  output file =  ${output_file} "
        bin/champsim --warmup_instructions "$warmup_instructions" --simulation_instructions "$simulation_instructions" "${batch[@]}" > "$output_file"
    done
    
    echo "Simulation Finished"
done