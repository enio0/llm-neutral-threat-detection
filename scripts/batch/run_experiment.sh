#!/bin/bash
#SBATCH --job-name=hct-experiment
#SBATCH --partition=adula
#SBATCH --cpus-per-task=6
#SBATCH --time=12:00:00
#SBATCH --gres=gpu:2
#SBATCH --mem=48G
#SBATCH --output=experiment_output_%j.log
#SBATCH --container-image=/slurm/containers/massif-mamba.sqsh

echo "=== Job Info ==="
echo "Job ID:     $SLURM_JOB_ID"
echo "Node:       $SLURMD_NODENAME"
echo "GPUs:       $CUDA_VISIBLE_DEVICES"
echo "CPUs:       $SLURM_CPUS_PER_TASK"
echo "Start time: $(date)"
echo "================"

nvidia-smi || echo "WARNING: no GPU visible to this job"

cd ~/thesisprj

export HF_TOKEN=""

# Execute the experiment
mamba run -p ./env python code_llm_experiment.py

echo "=== Job Finished ==="
echo "End time: $(date)"

