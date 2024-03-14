# PARGMF: A Provenance-enabled Automated Rule Generation and Matching Framework with Multi-level Attack Description Model

With the rapidly increasing volume of cyber-attacks over the past years due to the new working-from-homeparadigm, protecting hosts, networks, and individuals from cyber threats is in higher demand than ever.One promising solution are Provenance-based Intrusion Detection Systems (PIDS), which correlate host-basedsecurity logs to generate provenance graphs that describe the causal relationship between system entities. PIDShave shown significant potential in enhancing detection performance and reducing false alarms compared totraditional Intrusion Detection Systems (IDS). Rule-based approaches used in PIDS utilize expert-defined rulesets to identify known malicious patterns in provenance graphs. Although these rule-based techniques havebeen widely applied, they can only detect known attack patterns, are heavily dependent on the quality ofthe rules, and creating rules manually is time-consuming. To address these shortcomings, this study proposedtwo novel techniques: the Multi-level Attack Description Model (MADM) for describing attack patterns atmultiple granularity levels and the Provenance-enabled Automated Rule Generation and Matching Framework(PARGMF) to generate rules deterministically and promptly. We evaluated the proposed approaches usingthe DARPA OpTC dataset, complemented by a practical case study. This case study involved a prototypeextension for the CAPEv2 sandbox environment, demonstrating the real-world applicability of our approaches.Our results demonstrate, firstly, that PARGMF generates rules deterministically with an average processingtime of only 13.11 s compared to multiple hours or even days for manual rule creation by security experts.Secondly, through generalization of attack descriptions, MADM enhanced the robustness of rules by 21.9%for Behavioural Attack Description (BAD) and 25% for Structural Attack Description (SAD) compared toapproaches without generalization. Another added benefit compared to existing approaches is that PARGMFalso generates differential graphs to support security experts’ timely validation of security alarms.

- https://doi.org/https://doi.org/10.1016/j.jisa.2023.103682

## Citation

If you use the code in this repository, please cite the following paper:
```
@article{ZIPPERLE2024103682,
title = {PARGMF: A provenance-enabled automated rule generation and matching framework with multi-level attack description model},
journal = {Journal of Information Security and Applications},
volume = {81},
pages = {103682},
year = {2024},
issn = {2214-2126},
doi = {https://doi.org/10.1016/j.jisa.2023.103682}
}
```

## PARGMF CAPEv2 Demonstrator

### General Installation

- Install CAPEv2 Sandbox environment
    - https://capev2.readthedocs.io/en/latest/installation/index.html

- Install required python packages in the CAPEv2 python environment
  - `pip install -r requirements.txt`

### Configuration PARGMF demonstrator
- Copy `pargmf.py` and `utils.py` to `<cape_root>/module/processing/pargmf`
- Enable the module by adding the following configuration to `<cape_root>/processing.conf`
    ```
    [pargmf]
    enabled = True
    ```
- Restart the service
    - `service cape-processor restart`

### General Usage
- Run any file in the malware sandbox, either via the web interface or API
- PARGMF demonstrator will automatically run the processing after the file has been successfully executed
- The results will be in the following folder:
    -   `<cape_root>/storage/analysis/<id>/pargmf`
- The results contain the following files
    - `graph_df.pickle` - security logs in pandas DataFrame
    - `graph_analysis_result.json` - graph analytics results
    - `<filename>_full_attack_graph.png` - visualization of the full attack graph
    - `<filename>_behavioural_attack_graph.png` - visualization of the behavioral attack graph
    - `<filename>_structural_attack_graph.png` - visualization of the structural attack graph
    - `<filename>_full_attack_description_rules.json` - Full Attack Description (FAD) rules
    - `<filename>_behavioural_attack_description_rules.json` - Behavioral Attack Description (BAD) rules
    - `<filename>_structural_attack_description_rules.json` - Structural Attack Description (SAD) rules

### TODO/Limitations

- At the moment, the demonstrator is not integrated in the web interface
- The experiments have to be started manually (see in the following section)

## Experimental Evaluation

### General Usage
- Use the functions from `experimental_evaluation.py` from a jupyter notebook

### Run own experiments
- Run the experiment
    -  `evaluate_sandbox_results(input_folder, first_experiment, last_experiment, baseline_experiment)`
       - `input_folder`: E.g. `<cape_root>/storage/analysis/`
       - `first_experiment`: ID of the first experiment
       - `last_experiment`: ID of the last experiment
       - `baseline_experiment`: ID of the baseline experiment

### Analysis of the result

  - Analyze the experiment results:
    - `evaluate_sandbox_results()`
      - `input_folder`: Path to the folder containing the sandbox results
      -  `start_id`: ID of the first experiment
      -  `end_id`: ID of the last experiment
      -  `baseline_experiment`: ID of the baseline experiment. Defaults to None.

  - Create a differential graph:
    - `create_differential_graph(df, id1, id2, generalization, node_filters)`
      - `df`: Output of `evaluate_sandbox_results()`
      - `id1`: ID of the first experiment
      - `id2`: ID of the second experiment
      - `generalization`: Select the MADM - either FULL, BEHAVIOURAL, or STRUCTURAL
      - `node_filters`: Apply node filters to improve the readability
  - Visualize a particular attack graph:
    - `draw_experiment_graph(df, id, generalization, node_filters)`
      - `df`: Output of `evaluate_sandbox_results()`
      - `id`: ID of the experiment
      - `generalization`: Select the MADM - either FULL, BEHAVIOURAL, or STRUCTURAL
      - `node_filters`: Apply node filters to improve the readability

## License

This work is licensed under a CC BY 4.0 license.
