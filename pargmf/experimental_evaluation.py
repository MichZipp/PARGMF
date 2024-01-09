
import glob
import os
import json as json
from tqdm import tqdm
import pandas as pd
import numpy as np

from utils import *

def evaluate_sandbox_results(input_folder: str, start_id: int, end_id: int, baseline_experiment: int=None) -> pd.DataFrame:
    """
    Evaluate the sandbox results of a set of experiments

    Args:
        input_folder (str): Path to the folder containing the sandbox results
        start_id (int): ID of the first experiment
        end_id (int): ID of the last experiment
        baseline_experiment (int, optional): ID of the baseline experiment. Defaults to None.

    Returns:
        df (pd.DataFrame): Dataframe containing the experiment results
    """

    if baseline_experiment is None:
        baseline_experiment = start_id

    experiments = dict()

    for input_path in tqdm(glob.glob(input_folder + "/*")):
        try:
            experiment_id = int(input_path.replace(input_folder + '/', ''))
        except ValueError:
            continue

        if experiment_id < start_id or experiment_id > end_id:
            continue
        analysis_result_path = os.path.join(input_path, 'graph', "graph_analysis_result.json")
        graph_df_path = os.path.join(input_path, 'graph', "graph_df.pickle")
        with open(analysis_result_path, 'r') as f:
            analysis_result = json.load(f)
        
        filename = analysis_result['metadata']['filename']
        package = analysis_result['metadata']['package']
        costum = json.loads(analysis_result['metadata']['custom'].replace("'", '"'))
        experiment_group = costum['experiment_group']
        exfilitration_type = costum['exfiltration']
        machine = costum['machine']


        if package == 'doc':
            executable = 'winword.exe'
        elif package == 'xls':
            executable = 'excel.exe'
        elif package == 'ps1':
            executable = 'pwsh.exe'
        else:
            print(f"Unknown package: {package}")
        

        experiments[int(experiment_id)] = {
            'experiment': experiment_group,
            'filename': filename,
            'package': package,
            'executable': executable,
            'experiment_group': experiment_group,
            'exfiltration_type': exfilitration_type,
            'machine': machine,
            'path' : input_path,
            'graph_df_path': graph_df_path,     
            'graph': {
                'nodes': 0,
                'edges': 0,
            },            
            'attack_graph': {
                'nodes': 0,
                'edges': 0,
                'reduction': 0
            },
            'behavioural_attack_graph': {
                'nodes': 0,
                'edges': 0,
                'reduction': 0
            },
            'structural_attack_graph': {
                'nodes': 0,
                'edges': 0,
                'reduction': 0
            }
        }

    
    baseline_df = pd.read_pickle(experiments[baseline_experiment]['graph_df_path'])
    filename = experiments[baseline_experiment]['filename']
    executable = experiments[baseline_experiment]['executable']
    identifiers = get_node_of_interest_identifiers(baseline_df, filename, executable)

    baseline_structural_df = structural_generalization(baseline_df)
    baseline_behavioural_df = behavioural_generalization(baseline_df, keep_process_chain=False, optc=False)
    
    # Parse df to graph
    baseline_graph = to_graph(baseline_df)
    baseline_structural_graph = to_graph(baseline_structural_df)
    baseline_behavioural_graph = to_graph(baseline_behavioural_df)

    baseline_attack_graph = filter_by_node_identifiers(baseline_graph, identifiers, ancestors=False)
    baseline_structural_attack_graph = filter_by_node_identifiers(baseline_structural_graph, identifiers, ancestors=False, ignore_first_hop=False)
    baseline_behavioural_attack_graph = filter_by_node_identifiers(baseline_behavioural_graph, identifiers, ancestors=False, ignore_first_hop=False)

    del baseline_structural_graph, baseline_behavioural_graph
    del baseline_structural_df, baseline_behavioural_df

    for experiment_id, experiment in tqdm(experiments.items()):
        if experiment_id == baseline_experiment:
            experiment['graph']['nodes'] = baseline_graph.number_of_nodes()
            experiment['graph']['edges'] = baseline_graph.number_of_edges()

            experiment['attack_graph']['nodes'] = baseline_attack_graph.number_of_nodes()
            experiment['attack_graph']['edges'] = baseline_attack_graph.number_of_edges()
            experiment['attack_graph']['reduction'] = round(100 - (baseline_attack_graph.number_of_nodes() / baseline_graph.number_of_nodes() * 100),2)

            experiment['structural_attack_graph']['nodes'] = baseline_structural_attack_graph.number_of_nodes()
            experiment['structural_attack_graph']['edges'] = baseline_structural_attack_graph.number_of_edges()
            experiment['structural_attack_graph']['reduction'] = round(100 - (baseline_structural_attack_graph.number_of_nodes() / baseline_graph.number_of_nodes() * 100),2)

            experiment['behavioural_attack_graph']['nodes'] = baseline_behavioural_attack_graph.number_of_nodes()
            experiment['behavioural_attack_graph']['edges'] = baseline_behavioural_attack_graph.number_of_edges()
            experiment['behavioural_attack_graph']['reduction'] = round(100 - (baseline_behavioural_attack_graph.number_of_nodes() / baseline_graph.number_of_nodes() * 100),2)
            continue
        experiment_df = pd.read_pickle(experiment['graph_df_path'])
        experiment_structural_df = structural_generalization(experiment_df)
        experiment_behavioural_df = behavioural_generalization(experiment_df, keep_process_chain=False, optc=False)

        # Parse df to graph
        experiment_graph = to_graph(experiment_df)
        experiment_structural_graph = to_graph(experiment_structural_df)
        experiment_behavioural_graph = to_graph(experiment_behavioural_df)

        identifiers = get_node_of_interest_identifiers(experiment_df, experiment['filename'], experiment['executable'])

        experiment_attack_graph = filter_by_node_identifiers(experiment_graph, identifiers, ancestors=False)

        experiment_structural_attack_graph = filter_by_node_identifiers(experiment_structural_graph, identifiers, ancestors=False, ignore_first_hop=False)
        experiment_behavioural_attack_graph = filter_by_node_identifiers(experiment_behavioural_graph, identifiers, ancestors=False, ignore_first_hop=False)

        experiment['graph']['nodes'] = experiment_graph.number_of_nodes()
        experiment['graph']['edges'] = experiment_graph.number_of_edges()

        experiment['attack_graph']['nodes'] = experiment_attack_graph.number_of_nodes()
        experiment['attack_graph']['edges'] = experiment_attack_graph.number_of_edges()
        experiment['attack_graph']['reduction'] = round(100 - (experiment_attack_graph.number_of_nodes() / experiment_graph.number_of_nodes() * 100),2)

        experiment['structural_attack_graph']['nodes'] = experiment_structural_attack_graph.number_of_nodes()
        experiment['structural_attack_graph']['edges'] = experiment_structural_attack_graph.number_of_edges()
        experiment['structural_attack_graph']['reduction'] = round(100 - (experiment_structural_attack_graph.number_of_nodes() / experiment_graph.number_of_nodes() * 100),2)

        experiment['behavioural_attack_graph']['nodes'] = experiment_behavioural_attack_graph.number_of_nodes()
        experiment['behavioural_attack_graph']['edges'] = experiment_behavioural_attack_graph.number_of_edges()
        experiment['behavioural_attack_graph']['reduction'] = round(100 - (experiment_behavioural_attack_graph.number_of_nodes() / experiment_graph.number_of_nodes() * 100),2)
    
        experiment['graph']['sig_matching'] = graph_includes_singniture_edges(baseline_graph, experiment_graph, score=True)
        experiment['attack_graph']['sig_matching'] = graph_includes_singniture_edges(baseline_attack_graph, experiment_attack_graph, score=True)
        experiment['structural_attack_graph']['sig_matching'] = graph_includes_singniture_edges(baseline_structural_attack_graph, experiment_structural_attack_graph, score=True)
        draw_graph_graphviz(baseline_behavioural_attack_graph, filename='baseline_behavioural_attack_graph' + str(experiment_id) + '.png')
        draw_graph_graphviz(experiment_behavioural_attack_graph, filename='experiment_behavioural_attack_graph' + str(experiment_id) + '.png')
        experiment['behavioural_attack_graph']['sig_matching'] = graph_includes_singniture_edges(baseline_behavioural_attack_graph, experiment_behavioural_attack_graph, score=True)

    
    tmp = list()
    for id, experiment in experiments.items():
        experiment.update({'id': id})
        tmp.append(experiment)

    df = pd.json_normalize(tmp)

    df.set_index('id', inplace=True)
    df.sort_index(ascending=True, inplace=True)
    df.columns = df.columns.str.split('.', expand=True)
    return df



