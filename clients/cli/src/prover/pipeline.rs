//! Proving pipeline that orchestrates the full proving process

use super::engine::ProvingEngine;
use super::input::InputParser;
use super::types::ProverError;
use crate::environment::Environment;
use crate::task::Task;
use chrono::Local;
use nexus_sdk::stwo::seq::Proof;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Orchestrates the complete proving pipeline
pub struct ProvingPipeline;

impl ProvingPipeline {
    /// Execute authenticated proving for a task
    pub async fn prove_authenticated(
        task: &Task,
        environment: &Environment,
        client_id: &str,
    ) -> Result<(Proof, String, Vec<String>), ProverError> {
        match task.program_id.as_str() {
            "fib_input_initial" => Self::prove_fib_task(task, environment, client_id).await,
            _ => Err(ProverError::MalformedTask(format!(
                "Unsupported program ID: {}",
                task.program_id
            ))),
        }
    }

    /// Process fibonacci proving task with multiple inputs
    async fn prove_fib_task(
        task: &Task,
        environment: &Environment,
        client_id: &str,
    ) -> Result<(Proof, String, Vec<String>), ProverError> {
        let all_inputs = task.all_inputs();

        if all_inputs.is_empty() {
            return Err(ProverError::MalformedTask(
                "No inputs provided for task".to_string(),
            ));
        }

        let mut proof_hashes = Vec::new();
        let mut final_proof = None;

        let mut proofs: Vec<Proof> =
            Self::prove_fib_task_parallel(all_inputs, task, environment, client_id).await?;
        for (_input_index, _input_data) in all_inputs.iter().enumerate() {
            // Step 3: Generate proof hash
            let proof: Proof = proofs.remove(0);
            let proof_hash = Self::generate_proof_hash(&proof);
            proof_hashes.push(proof_hash);
            final_proof = Some(proof);
        }

        let final_proof_hash = Self::combine_proof_hashes(task, &proof_hashes);

        Ok((
            final_proof.expect("No proof found"),
            final_proof_hash,
            proof_hashes,
        ))
    }

    /// Generate hash for a proof
    fn generate_proof_hash(proof: &Proof) -> String {
        let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
        format!("{:x}", Keccak256::digest(&proof_bytes))
    }

    /// Combine multiple proof hashes based on task type
    fn combine_proof_hashes(task: &Task, proof_hashes: &[String]) -> String {
        match task.task_type {
            crate::nexus_orchestrator::TaskType::AllProofHashes
            | crate::nexus_orchestrator::TaskType::ProofHash => {
                Task::combine_proof_hashes(proof_hashes)
            }
            _ => proof_hashes.first().cloned().unwrap_or_default(),
        }
    }

    async fn prove_fib_task_parallel(
        all_inputs: &[Vec<u8>],
        task: &Task,
        environment: &Environment,
        client_id: &str,
    ) -> Result<Vec<Proof>, ProverError> {
        let mut proofs: Vec<Proof> = Vec::new();
        let mut handler_map = HashMap::new();

        // export SUB_PROCESS_NUM=8
        let sub_process_num = if let Some(sub_process_num) = std::env::var_os("SUB_PROCESS_NUM") {
            sub_process_num
                .as_os_str()
                .to_str()
                .unwrap()
                .parse()
                .unwrap()
        } else {
            8
        };
        let semaphore = Arc::new(Semaphore::new(sub_process_num));
        println!("{} Prove {}", Self::get_prefix(), task);
        println!(
            "{} Sub process num: {}",
            Self::get_prefix(),
            sub_process_num
        );

        let start_time = Local::now().timestamp_millis();
        for (input_index, input_data) in all_inputs.iter().enumerate() {
            let permit = semaphore.clone().acquire_owned().await.unwrap();

            let input_index = input_index.clone();
            let input_data = input_data.clone();
            let task = task.clone();
            let environment = environment.clone();
            let client_id = client_id.to_string();
            let handler = tokio::spawn(async move {
                // Step 1: Parse and validate input
                let inputs = InputParser::parse_triple_input(&input_data).unwrap();
                println!(
                    "{} Process input: {} {}",
                    Self::get_prefix(),
                    input_index,
                    serde_json::to_string(&inputs).unwrap()
                );
                // Step 2: Generate and verify proof
                let proof =
                    ProvingEngine::prove_and_validate(&inputs, &task, &environment, &client_id)
                        .await
                        .unwrap();
                println!(
                    "{} Finished process input {}",
                    Self::get_prefix(),
                    input_index
                );
                drop(permit);
                proof
            });

            handler_map.insert(input_index, handler);
        }

        for (input_index, _input_data) in all_inputs.iter().enumerate() {
            if let Some(handle) = handler_map.remove(&input_index) {
                match handle.await {
                    Ok(result) => proofs.push(result),
                    Err(e) => eprintln!("Proof failed: {:?}", e),
                }
            } else {
                eprintln!("No handler found for input index: {}", input_index);
            }
        }
        println!(
            "{} Task {} ({} {}) finished in {}ms",
            Self::get_prefix(),
            task.task_id,
            task.task_type.as_str_name(),
            task.public_inputs_list.len(),
            Local::now().timestamp_millis() - start_time,
        );
        Ok(proofs)
    }

    fn get_prefix() -> String {
        format!("SubProcess [{}]", Local::now().format("%Y-%m-%d %H:%M:%S"))
    }
}
