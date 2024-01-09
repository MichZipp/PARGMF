from ast import Tuple
from copy import deepcopy
from enum import Enum, auto
import ipaddress
import logging
import ntpath
import os
import re
import pathlib
from typing import List, Set
import json
from loguru import logger
import numpy as np 
import pandas as pd
import networkx as nx
from IPython.display import SVG, Image
from evtx import PyEvtxParser
from shortuuid import uuid
from urllib.parse import urlparse
from tld import get_tld

log = logging.getLogger(__name__)


# Define data types
class ReturnType(Enum):
    LIST = 1
    DATAFRAME = 2

class NodeType(Enum):
    PROCESS = auto()
    IMAGE = auto()
    FILE = auto()
    HOST = auto()
    KEY = auto()
    REGISTRY = auto()
    PIPE = auto()
    SHELL = auto()
    MODULE = auto()
    FLOW = auto()

class EdgeType(Enum):
    CREATED_PROCESS = auto()
    USED = auto()
    IS_A = auto()
    MODIFIED_TIME = auto()
    CONNECTED = auto()
    TERMINATED = auto()
    LOADED = auto()
    ACCESSED = auto()
    DELETED = auto()
    FILESTREAM = auto()
    RENAMED_KEY = auto()
    RENAMED_VALUE = auto()
    VALUE_SET = auto()
    CREATED_PIPE = auto()
    CONNECTED_PIPE = auto()
    DNS_QUERY = auto()
    CREATED_REMOTE_THREAD = auto()
    CREATED_FILE = auto()
    CREATED_KEY = auto()
    USED_COMMAND = auto()
    INTERACTED = auto()

class Generalization(Enum):
    FULL = auto()
    BEHAVIOURAL = auto()
    STRUCTURAL = auto()

port_mappings = {
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    43: 'whois',
    53: 'dns',
    67: 'dhcp',
    68: 'dhcp',
    70: 'gopher',
    79: 'finger',
    80: 'http',
    110: 'pop3',
    119: 'nntp',
    143: 'imap',
    194: 'irc',
    389: 'ldap',
    443: 'https',
    465: 'smtps',
    587: 'smtp',
    636: 'ldaps',
    993: 'imaps',
    995: 'pop3s',
    1723: 'pptp',
    3306: 'mysql',
    3389: 'rdp',
    5900: 'vnc',
    8080: 'http'
}


class SysmonEvent():
    def __init__(self, event_id: int, event_data: dict, computer_name: str):
        self.event_id = event_id
        self.topic = "sysmon" + str(event_id)
        self.computer_name = computer_name
        self.event_data = event_data

    def append_event_data(self, key, value):
        self.event_data[key] = value

    # Probably not the most efficient way?!
    def to_json(self) -> json:
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def to_dict(self):
        return self.__dict__


def process_sysmon(evtx_path: str, output_path: str, filename: str="doc1.doc", package: str="doc", custom: dict = None, logger=None):
    """
    Perform graph analytics on a Sysmon EVTX file for CAPEv2 processing.

    Args:
        evtx_path (str): The path to the Sysmon EVTX file.
        output_path (str): The path to the output folder.
        filename (str): The name of the file.
        package (str): The package type.
        custom (dict): The custom options.
        logger (object): The logger object.

    Returns:
        dict: The graph analytics result.
    """

    # Set up logger if not provided
    if not logger:
        from loguru import logger

    result = dict()

    # Parse evtx file to a DataFrame
    df_prettified = parse_file(evtx_path, [10], prettified=True)

    # Get structural and behavioral DataFrames
    structural_df = structural_generalization(df_prettified)
    behavioural_df = behavioural_generalization(df_prettified)

    # Save DataFrame to a pickle file
    df_prettified.to_pickle(os.path.join(output_path, 'graph_df.pickle'))

    # Convert DataFrames to graphs
    graph = to_graph(df_prettified)
    behavioural_graph = to_graph(behavioural_df)
    structural_graph = to_graph(structural_df)

    # Set executable based on package
    executable = None
    if package == "doc":
        executable = "winword.exe"
    elif package == "ps1":
        executable = "pwsh.exe"
    elif package == "xls":
        executable = "excel.exe"

    # Print information
    print(f"Filename: {filename}")
    print(f"Executable: {executable}")
    print(f"Package: {package}")

    # Apply forward tracing
    identifiers = get_node_of_interest_identifiers(df_prettified, filename, executable)
    if identifiers:
        process_centric_graph = filter_by_node_identifiers(graph, identifiers, ancestors=False, ignore_first_hop=True)
        process_centric_structural_graph = filter_by_node_identifiers(structural_graph, identifiers, ancestors=False, ignore_first_hop=True)
        process_centric_behavioural_graph = filter_by_node_identifiers(behavioural_graph, identifiers, ancestors=False, ignore_first_hop=True)

    # Get graph statistics
    result['metadata'] = dict()
    result['metadata']['filename'] = filename
    result['metadata']['package'] = package
    result['metadata']['custom'] = custom
    result['graph'] = graph_analytics(graph)
    result['structural_graph'] = graph_analytics(structural_graph)
    result['behavioural_graph'] = graph_analytics(behavioural_graph)
    if identifiers:
        result['process_centric_graph'] = graph_analytics(process_centric_graph)
        result['process_centric_structural_graph'] = graph_analytics(process_centric_structural_graph)
        result['process_centric_behavioural_graph'] = graph_analytics(process_centric_behavioural_graph)

    # Save graph statistics to a JSON file
    with open(os.path.join(output_path, "graph_analysis_result.json"), "w") as f:
        f.write(json.dumps(result))
        f.close()

    # Save graphs as images
    if identifiers:
        draw_graph_graphviz(process_centric_graph, notebook=False, filename=os.path.join(output_path, filename + "_full_attack_graph" + ".png"), draw_clusters=False)
        draw_graph_graphviz(process_centric_structural_graph, notebook=False, filename=os.path.join(output_path, filename + "_behavioural_attack_graph" + ".png"), draw_clusters=False)
        draw_graph_graphviz(process_centric_behavioural_graph, notebook=False, filename=os.path.join(output_path, filename + "_structural_attack_graph" + ".png"), draw_clusters=False)
    else:
        draw_graph_graphviz(graph, notebook=False, filename=os.path.join(output_path, filename + "_graph" + ".png"), draw_clusters=False)

    # Generate rules
    full_attack_description_rules = get_signatures(process_centric_graph)
    behavioural_attack_description_rules = get_signatures(process_centric_behavioural_graph)
    structural_attack_description_rules = get_signatures(process_centric_structural_graph)

    # Save rules to a JSON file
    with open(os.path.join(output_path, "full_attack_description_rules.json"), "w") as f:
        f.write(json.dumps(full_attack_description_rules))
        f.close()

    with open(os.path.join(output_path, "behavioural_attack_description_rules.json"), "w") as f:
        f.write(json.dumps(behavioural_attack_description_rules))
        f.close()
    
    with open(os.path.join(output_path, "structural_attack_description_rules.json"), "w") as f:
        f.write(json.dumps(structural_attack_description_rules))
        f.close()


def structural_generalization(input_df: pd.DataFrame, remove_edge_types: bool = False) -> pd.DataFrame:
    """
    Perform structural generalization on a DataFrame.

    Args:
        input_df (pd.DataFrame): The input DataFrame to process.
        remove_edge_types (bool): If True, remove edge types and set them all to INTERACTED. Default is False.

    Returns:
        pd.DataFrame: A DataFrame with structural generalization applied.
    """

    # Create a copy of the input DataFrame to avoid modifying the original
    df = input_df.copy()

    # Update source_id and source_label based on the source_type and NodeType
    df.source_id = df.apply(lambda row: row.source_type if NodeType[row.source_type] is not NodeType.PROCESS else row.source_label, axis=1)
    df.source_label = df.apply(lambda row: row.source_type if NodeType[row.source_type] is not NodeType.PROCESS else row.source_label, axis=1)

    # Update target_id and target_label based on the target_type and NodeType
    df.target_id = df.apply(lambda row: row.target_type if NodeType[row.target_type] is not NodeType.PROCESS else row.target_label, axis=1)
    df.target_label = df.apply(lambda row: row.target_type if NodeType[row.target_type] is not NodeType.PROCESS else row.target_label, axis=1)

    # If remove_edge_types is True, set all edge types to INTERACTED
    if remove_edge_types:
        df.edge_type = EdgeType.INTERACTED.name

    # If edge_feature column exists, drop it
    if 'edge_feature' in df.columns:
        df.drop(columns=['edge_feature'], inplace=True)

    # Group by all columns, reset index and count the size of each group
    df = df.groupby(df.columns.tolist(), as_index=False).size()

    # Create a new edge_label column based on edge_type and the count ('size') of each group
    df['edge_label'] = df.apply(lambda row: row.edge_type + ' [' + str(row['size']) + ']', axis=1)

    # Rename the 'size' column to 'edge_feature'
    df.rename(columns={'size': 'edge_feature'}, inplace=True)

    # Drop duplicates from the DataFrame
    df.drop_duplicates(inplace=True)

    # Return the processed DataFrame
    return df

def generalize_node_label(row: pd.Series, optc: bool = False, gen_modules_as_files: bool = False):
    """
    Generalize the node label based on the NodeType.

    Args:
        row (pd.Series): A row from the DataFrame containing the target_type and target_label.
        optc (bool): If True, use OPTC-specific generalization. Default is False.
        gen_modules_as_files (bool): If True, treat modules as files for generalization. Default is False.

    Returns:
        str: The generalized node label.
    """

    # Generalize registry keys
    if NodeType[row.target_type] == NodeType.KEY or NodeType[row.target_type] == NodeType.REGISTRY:
        if optc:
            return generalize_registry_key_optc(row.target_label)
        else:
            return generalize_registry_key(row.target_label)

    # Generalize IP addresses
    elif NodeType[row.target_type] == NodeType.HOST or NodeType[row.target_type] == NodeType.FLOW:
        return generalize_ip(row.target_label)

    # Generalize file names
    elif NodeType[row.target_type] == NodeType.FILE:
        if row.target_label.endswith('.exe'):
            return get_filename(row.target_label)
        else:
            return generalize_filename(row.target_label)

    # Generalize module names
    elif NodeType[row.target_type] == NodeType.MODULE:
        if gen_modules_as_files:
            return generalize_filename(row.target_label)
        else:
            return generalize_module(row.target_label)

    # Don't do anything for pipes yet
    elif NodeType[row.target_type] == NodeType.PIPE:
        return row.target_label

    # Generalize shell commands
    elif NodeType[row.target_type] == NodeType.SHELL:
        if optc:
            return generalize_payload_in_shell(row.target_label)
        else:
            return generalize_command_line(row.target_label)

    # Print the target_type if it doesn't match any of the above conditions
    else:
        print(NodeType[row.target_type])

def behavioural_generalization(input_df: pd.DataFrame, keep_process_chain: bool = True, optc: bool = False, gen_modules_as_files: bool = False) -> pd.DataFrame:
    """
    Perform behavioural generalization on a DataFrame.

    Args:
        input_df (pd.DataFrame): The input DataFrame to process.
        keep_process_chain (bool): If True, keep the process chain. Default is True.
        optc (bool): If True, use 'PROCESS_CREATE' in the process. Default is False.
        gen_modules_as_files (bool): If True, treat modules as files for generalization. Default is False.

    Returns:
        pd.DataFrame: A DataFrame with behavioural generalization applied.
    """

    # Create a copy of the input DataFrame to avoid modifying the original
    df = input_df.copy()

    # Drop duplicates from the DataFrame
    df.drop_duplicates(inplace=True)

    process_mapping = dict()
    image_count = dict()

    if keep_process_chain:
        # Loop through the sorted DataFrame and populate the process_mapping dictionary
        for _, row in df.sort_values(by=['edge_feature']).drop_duplicates().iterrows():
            process_mapping[row['source_id']] = row['source_label']
            if row['target_id'] not in process_mapping:
                process_mapping[row['target_id']] = row['target_label']

        # Update the process_mapping dictionary and image_count dictionary
        for id, label in process_mapping.items():
            if label not in image_count:
                process_mapping[id] = label
                image_count[label] = 1
            else:
                process_mapping[id] = f'{label}_{image_count[label]}'
                image_count[label] += 1

    # Replace process id with process image
    df['source_id'] = df.apply(lambda row: process_mapping[row['source_id']] if keep_process_chain else row['source_label'], axis=1)

    # Generalize target node labels, but not nodes which are processes
    df['target_id'] = df.apply(lambda row: generalize_node_label(row, optc, gen_modules_as_files) if NodeType[row.target_type] is not NodeType.PROCESS else process_mapping[row['target_id']] if keep_process_chain else row['target_label'], axis=1)

    # Update source_label and target_label based on source_id and target_id
    df['target_label'] = df.apply(lambda row: row['target_id'], axis=1)
    df['source_label'] = df.apply(lambda row: row['source_id'], axis=1)

    # If edge_feature column exists, drop it
    if 'edge_feature' in df.columns:
        df.drop(columns=['edge_feature'], inplace=True)

    # Group by all columns, reset index and count the size of each group
    df = df.groupby(df.columns.tolist(), as_index=False).size()

    # Create a new edge_label column based on edge_type and the count ('size') of each group
    df['edge_label'] = df.apply(lambda row: row.edge_type + ' [' + str(row['size']) + ']', axis=1)

    # Rename the 'size' column to 'edge_feature'
    df.rename(columns={'size': 'edge_feature'}, inplace=True)

    # Update the target_id based on the target_type
    df['target_id'] = df.apply(lambda row: row['target_id'] + '_' + row['target_type'] if NodeType[row['target_type']] != NodeType.PROCESS else row['target_id'], axis=1)

    # Drop duplicates from the DataFrame
    df.drop_duplicates(inplace=True)

    # Return the processed DataFrame
    return df


def parse_file(file_path: str, filters: List[int] = list(), time_zone: str = "Australia/Sydney", computer_name: str = uuid(), return_type: ReturnType = ReturnType.DATAFRAME, prettified: bool = True) -> ReturnType:
    """
    Parse a Sysmon EVTX file and return a list of SysmonEvent objects or a DataFrame.

    Args:
        file_path (str): The path to the Sysmon EVTX file.
        filters (List[int]): A list of event IDs to filter out.
        time_zone (str): The time zone to use for the timestamps. Default is "Australia/Sydney".
        computer_name (str): The name of the computer. Default is a random UUID.
        return_type (ReturnType): The return type. Default is ReturnType.DATAFRAME.
        prettified (bool): If True, return a prettified DataFrame. Default is True.
    
    Returns:
        ReturnType: A list of SysmonEvent objects or a DataFrame.
    """
    # Create a PyEvtxParser object for the given file_path
    parser = PyEvtxParser(file_path)

    # Retrieve event records as JSON
    records = parser.records_json()

    # Initialize an empty list to store SysmonEvent objects
    events: List[SysmonEvent] = []

    # Iterate over the records and create SysmonEvent objects
    for record in records:
        record = json.loads(record["data"])
        event_data = record["Event"]["EventData"]
        event_id = record["Event"]["System"]["EventID"]
        events.append(SysmonEvent(event_id=event_id,
                                  event_data=event_data, computer_name=computer_name))

    # Return the list of events if the return type is LIST
    if return_type is ReturnType.LIST:
        return events
    else:
        # Convert the list of SysmonEvent objects to a DataFrame
        event_list = list()
        for event in events:
            if event.event_id not in filters:
                event_as_dict = event.event_data
                event_as_dict["EventId"] = event.event_id
                event_list.append(event_as_dict)

        sysmon_df = pd.DataFrame.from_dict(event_list)

        # Replace illegal characters in the DataFrame (e.g., for Graphviz compatibility)
        sysmon_df.replace(to_replace=r'\\', value='/',
                          regex=True, inplace=True)
        sysmon_df.replace(to_replace=r'ADMINI~1',
                          value='ADMINISTRATOR', regex=True, inplace=True)

        # Convert UTC time to pandas timestamp and localize
        if "UtcTime" in sysmon_df.columns:
            sysmon_df.UtcTime = pd.to_datetime(sysmon_df.UtcTime)
            sysmon_df["Timestamp"] = sysmon_df.UtcTime.dt.tz_localize(
                "UTC").dt.tz_convert(time_zone)

        # Return the prettified or original DataFrame, based on the 'prettified' parameter
        if prettified:
            return prettify(sysmon_df)
        else:
            return sysmon_df


def check_for_dns_name(input: str, dns_queries_dict: dict):
    """
    Check if the input string is a DNS name.

    Args:
        input (str): The input string.
        dns_queries_dict (dict): A dictionary containing DNS queries.
    
    Returns:
        str: The DNS name if the input string is a DNS name, otherwise None.
    """

    # Split the input string into IP and port using the provided utility function
    ip, port = split_ip_port(input)

    # Check if the IP is in the dns_queries_dict and return the corresponding DNS name
    if ip in dns_queries_dict:
        return dns_queries_dict[ip] + ':' + str(port)
    else:
        # If the IP is not found in the dns_queries_dict, return the original input string
        return input


def prettify(input: pd.DataFrame, debug: bool = False) -> pd.DataFrame:
    """
    Prettiy a EVTX DataFrame by adding additional columns and converting column values to strings.

    Args:
        input (pd.DataFrame): The input EVTX DataFrame
        debug (bool): If True, print debug information. Default is False.

    Returns:
        pd.DataFrame: A prettified EVTX DataFrame.
    """

    data = list()

    # Convert to lowercase
    for column in input.columns:
        if input[column].dtypes in [object]:
            input[column] = input[column].astype('str')
            input[column] = input[column].str.lower()

    for _, row in input.iterrows():
        if row.EventId == 1:
            data.append([row.EventId, row.ParentProcessGuid, NodeType.PROCESS.name, get_filename(row.ParentImage), row.ProcessGuid,
                         NodeType.PROCESS.name, get_filename(row.Image), EdgeType.CREATED_PROCESS.name, row.Timestamp])

            command_line = parse_command_line(row.Image, row.CommandLine)
            if command_line and command_line.isspace() is False:
                data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(row.Image),command_line, NodeType.SHELL.name, command_line, EdgeType.USED_COMMAND.name, row.Timestamp])
        elif row.EventId == 2:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), row.TargetFilename, NodeType.FILE.name, row.TargetFilename, EdgeType.MODIFIED_TIME.name, row.Timestamp])
        elif row.EventId == 3:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(row.Image), row.DestinationIp + ':' + str(int(
                row.DestinationPort)), NodeType.HOST.name, row.DestinationIp + ':' + str(int(row.DestinationPort)), EdgeType.CONNECTED.name, row.Timestamp])
        elif row.EventId == 5:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(row.Image), row.ProcessGuid,
                         NodeType.PROCESS.name, get_filename(row.Image), EdgeType.TERMINATED.name, row.Timestamp])
        elif row.EventId == 8:
            data.append([row.EventId, row.SourceProcessGuid, NodeType.PROCESS.name, get_filename(row.SourceImage), row.TargetProcessGuid,
                         NodeType.PROCESS.name, get_filename(row.TargetImage), EdgeType.CREATED_REMOTE_THREAD.name, row.Timestamp])
        elif row.EventId == 10:
            data.append([row.EventId, row.SourceProcessGuid, NodeType.PROCESS.name, get_filename(row.SourceImage), row.TargetProcessGuid,
                         NodeType.PROCESS.name, get_filename(row.TargetImage), EdgeType.ACCESSED.name, row.Timestamp])
        elif row.EventId == 11:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), row.TargetFilename, NodeType.FILE.name, row.TargetFilename, EdgeType.CREATED_FILE.name, row.Timestamp])
        elif row.EventId == 12:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), row.TargetObject, NodeType.KEY.name, row.TargetObject, EdgeType.CREATED_KEY.name, row.Timestamp])
        elif row.EventId == 13:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), row.TargetObject, NodeType.KEY.name, row.TargetObject, EdgeType.VALUE_SET.name, row.Timestamp])
        elif row.EventId == 14:
            if row.EventType == "RenameKey":
                data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                    row.Image), row.TargetObject, NodeType.KEY.name, row.TargetObject, EdgeType.RENAMED_KEY.name, row.Timestamp])
            else:
                data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                    row.Image), row.TargetObject, NodeType.KEY.name, row.TargetObject, EdgeType.RENAMED_VALUE.name, row.Timestamp])
        elif row.EventId == 15:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), row.TargetFilename, NodeType.FILE.name, row.TargetFilename, EdgeType.FILESTREAM.name, row.Timestamp])
        elif row.EventId == 17:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), row.PipeName, NodeType.PIPE.name, row.PipeName, EdgeType.CREATED_PIPE.name, row.Timestamp])
        elif row.EventId == 18:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), row.PipeName, NodeType.PIPE.name, row.PipeName, EdgeType.CONNECTED_PIPE.name, row.Timestamp])
        elif row.EventId == 22:
            target_id = get_ip_from_dns_query_result(row.QueryResults)
            if target_id == None:
                target_id = row.QueryName
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), target_id, NodeType.HOST.name, row.QueryName, EdgeType.DNS_QUERY.name, row.Timestamp])
        elif row.EventId == 23:
            data.append([row.EventId, row.ProcessGuid, NodeType.PROCESS.name, get_filename(
                row.Image), row.TargetFilename, NodeType.FILE.name, row.TargetFilename, EdgeType.DELETED.name, row.Timestamp])
        else:
            if debug:
                logger.error(f"EventId {row.EventId} not found!")
                logger.debug(f"Event: {row}")

    df = pd.DataFrame(data, columns=['id', 'source_id', 'source_type', 'source_label',
                                     'target_id', 'target_type', 'target_label', 'edge_type', 'edge_feature'])

    df['edge_label'] = df['edge_type']

    df['target_id'] = df.apply(
        lambda row: row.target_label if row.id == 3 else row.target_id, axis=1)

    # Drop dns queries for now
    df.drop(df[df['id'] == 22].index, inplace=True)

    # Check if a procss with image unknow <unknown process>
    rows_with_unknown_images = get_rows_containing_substring_in_column(df, '<unknown process>', 'source_label')

    for index, row in rows_with_unknown_images.iterrows():
        # Check for the source_id in the overall dataframe
        tmp_df = df[df['source_id'] == row['source_id']]
        for _, tmp_row in tmp_df.iterrows():
            if tmp_row['source_label'] != '<unknown process>':
                df.loc[index, 'source_label'] = tmp_row['source_label']
                break

        tmp_df = df[df['target_id'] == row['source_id']]
        for _, tmp_row in tmp_df.iterrows():
            if tmp_row['target_label'] != '<unknown process>':
                df.loc[index, 'source_label'] = tmp_row['target_label']
                break

    rows_with_unknown_images = get_rows_containing_substring_in_column(df, '<unknown process>', 'target_label')

    for index, row in rows_with_unknown_images.iterrows():
        # Check for the source_id in the overall dataframe
        tmp_df = df[df['target_id'] == row['target_id']]
        for _, tmp_row in tmp_df.iterrows():
            if tmp_row['target_label'] != '<unknown process>':
                df.loc[index, 'target_label'] = tmp_row['target_label']
                break


        tmp_df = df[df['source_id'] == row['target_id']]
        for _, tmp_row in tmp_df.iterrows():
            if tmp_row['source_label'] != '<unknown process>':
                df.loc[index, 'target_label'] = tmp_row['source_label']
                break

    # Replace invalid process guids
    df['source_id'] = df.apply(lambda row: row.source_id if row.source_type == NodeType.PROCESS.name and row.source_id != '00000000-0000-0000-0000-000000000000' else str(uuid()), axis=1)

    df['target_id'] = df.apply(lambda row: row.target_id if row.target_type == NodeType.PROCESS.name and row.target_id != '00000000-0000-0000-0000-000000000000' else str(uuid()), axis=1)

    return df


def to_graph(df: pd.DataFrame, optc: bool=False) -> nx.MultiDiGraph:
    """
    Convert a pandas dataframe to a networkx MultiDiGraph
    
    Args:
        df (pd.DataFrame): The input DataFrame to process.
        optc (bool): If True, use OPTC-specific generalization. Default is False.
    
    Returns:
        nx.MultiDiGraph: A MultiDiGraph.
    """
    
    nodes = list()
    edges_df = df[['source_id', 'target_id'] + [column for column in df.columns if column.startswith('edge')]].rename(columns={"edge_label": "label"}).drop_duplicates()
    for _, row in df.iterrows():
        nodes.append([row.source_id, row.source_type, row.source_label])
        nodes.append([row.target_id, row.target_type, row.target_label])

    nodes_df = pd.DataFrame(
        nodes, columns=['id', 'type', 'label']).drop_duplicates()


    # Dirty fix for duplicated ids - OLD
    duplicated_ids = get_rows_with_duplicated_column_values(nodes_df, columns=['id'])
    if len(duplicated_ids) >= 2:
        #  Usually a process with the same guid but different types such as Module and Image
        logger.info(f'There are {len(duplicated_ids["id"].unique())} duplicated ids in the nodes dataframe')

    for ids, group in nodes_df.groupby(['id', 'type'], as_index=False):
        if len(group['label'].unique()) > 1:
            len_first = len(df[(df['source_id'] == group.iloc[0]['id']) & (df['source_label'] == group.iloc[0]['label'])])
            len_second = len(df[(df['source_id'] == group.iloc[1]['id']) & (df['source_label'] == group.iloc[1]['label'])])
            if len_first > len_second:
                nodes_df.drop([group.index[1]], inplace=True)
            else:
                nodes_df.drop([group.index[0]], inplace=True)
    graph = nx.from_pandas_edgelist(
        edges_df, source='source_id', target='target_id', edge_attr=True, create_using=nx.MultiDiGraph)
    nx.set_node_attributes(graph, pd.Series(
        nodes_df.set_index('id').to_dict('index')))

    return graph

def get_node_of_interest_identifiers(df, filename, executable = None) -> List[str]:
    """
    Get the node of interest based on a filename and/or its executable.

    Args:
        df (pd.DataFrame): The input DataFrame to process.
        filename (str): The filename.
        executable (str): The executable. Default is None.
    
    Returns:
        List[str]: A list of node identifiers.
    """

    if executable:
        target_labels = get_rows_containing_substring_in_column(df, filename, 'target_label')
        target_labels_identifiers = target_labels[target_labels['source_type'] == 'PROCESS'][['source_id', 'source_label']].drop_duplicates()

        source_label = get_rows_containing_substring_in_column(df, executable, 'source_label')
        source_label_identifiers = source_label[source_label['source_type'] == 'PROCESS'][['source_id', 'source_label']].drop_duplicates()

        return target_labels_identifiers['source_id'].tolist() + target_labels_identifiers['source_label'].tolist() + source_label_identifiers['source_id'].tolist() + source_label_identifiers['source_label'].tolist()

    else:
        rows = get_rows_containing_substring_in_column(df, filename, column='source_label')
        node_of_interest_identifiers = rows[rows['source_type'] == 'PROCESS'][['source_id', 'source_label']].drop_duplicates()
        return node_of_interest_identifiers['source_id'].tolist() + node_of_interest_identifiers['source_label'].tolist()
    
def get_scenario_graph(graph: nx.MultiDiGraph, node_id: str, descendants: bool = True, ancestors: bool = True) -> Set[str]:
    """
    Get a scenario graph based on a node identifier.

    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        node_id (str): The node identifier.
        descendants (bool): If True, include descendants. Default is True.
        ancestors (bool): If True, include ancestors. Default is True.

    Returns:
        Set[str]: A set of node identifiers.
    """

    nodes = Set[str]
    nodes.add(node_id)

    # Forward tracing
    if descendants:
        nodes = set.union(nodes, nx.descendants(graph, node_id))

    # Backward tracing
    if ancestors:
        nodes = set.union(nodes, nx.ancestors(graph, node_id))
    
    return nodes

def filter_by_node_identifiers(graph: nx.MultiDiGraph, identifiers: List[str], descendants: bool = True, ancestors: bool = True, ignore_first_hop: bool = False) -> nx.MultiDiGraph:
    """
    Filter a graph by node identifiers.

    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        identifiers (List[str]): A list of node identifiers.
        descendants (bool): If True, include descendants. Default is True.
        ancestors (bool): If True, include ancestors. Default is True.
        ignore_first_hop (bool): If True, ignore the first hop. Default is False.

    Returns:
        nx.MultiDiGraph: A filtered NetworkX MultiDiGraph.
    """

    node_ids = [x for x,y in graph.nodes(data=True) if y['label'] in identifiers or x in identifiers]

    nodes = set()
    edges_to_remove = list()
    for node_id in node_ids:
        if ignore_first_hop:
            for edge in graph.edges(data=True):
                if edge[0] == node_id:
                    if EdgeType[edge[2]['edge_type']] not in [EdgeType.CREATED_PROCESS, EdgeType.TERMINATED]:
                        edges_to_remove.append((edge[0], edge[1]))
        nodes = set.union(nodes, get_scenario_graph(graph, node_id, descendants, ancestors))
    
    subgraph = graph.subgraph(nodes).copy()
    subgraph.remove_edges_from(edges_to_remove) 

    # Find nodes without edges
    nodes_to_remove = [x for  x in subgraph.nodes() if subgraph.degree(x) < 1]
    subgraph.remove_nodes_from(nodes_to_remove)
    return subgraph

def get_unique_node_labels_count(graph: nx.MultiDiGraph):
    """
    Get the count of unique node labels in a NetworkX MultiDiGraph.

    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.

    Returns:
        int: The count of unique node labels in the graph.
    """
    # Create a set to store unique node labels
    node_labels = set()

    # Iterate over all nodes in the graph
    for node in graph.nodes(data=True):
        # Add the node label to the set (this ensures uniqueness)
        node_labels.add(node[1]['label'])

    # Return the count of unique node labels
    return len(node_labels)

def get_unique_edge_labels_count(graph: nx.MultiDiGraph) -> int:
    """
    Get the count of unique edge labels in a NetworkX MultiDiGraph.

    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.

    Returns:
        int: The count of unique edge labels in the graph.
    """

    edge_labels = set()
    for edge in graph.edges(data=True):
        edge_labels.add(edge[2]['edge_type'])
    return len(edge_labels)

def get_node_type_frequencies(graph: nx.DiGraph = None) -> dict:
    """
    Get node type frequencies

    Args:
        graph (nx.DiGraph): A NetworkX DiGraph.

    Returns:
        dict: A dictionary containing node type frequencies.
    """
    node_types = nx.get_node_attributes(graph, "type")
    (unique, counts) = np.unique(list(node_types.values()), return_counts=True)
    node_type_frequencies = dict(zip(unique, counts))
    return [dict([a, int(x)] for a, x in node_type_frequencies.items())]

def get_edge_type_frequencies(graph: nx.DiGraph = None) -> dict:
    """
    Get edge type frequencies

    Args:
        graph (nx.DiGraph): A NetworkX DiGraph.
    
    Returns:
        dict: A dictionary containing edge type frequencies.
    """

    edge_types = nx.get_edge_attributes(graph, "edge_type")
    (unique, counts) = np.unique(list(edge_types.values()), return_counts=True)
    edge_type_frequencies = dict(zip(unique, counts))
    return [dict([a, int(x)] for a, x in edge_type_frequencies.items())]

def remove_cycle(graph: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """
    Remove cycle from graph
    
    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.

    Returns:
        nx.MultiDiGraph: A NetworkX MultiDiGraph without cycles.
    """
    tmp = deepcopy(graph)
    # Remove cycles
    while True:
        try:
            edge = nx.find_cycle(tmp)
            tmp.remove_edges_from(edge)
        except Exception as e:
            break
    return tmp

def get_longest_path(graph: nx.MultiDiGraph) -> int:
    """
    Get longest path
    
    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.
    
    Returns:
        int: The length of the longest path in the graph.
    """
    tmp = remove_cycle(graph)
    return nx.dag_longest_path_length(tmp)

def graph_analytics(graph: nx.DiGraph = None):
    """
    Get graph analytics

    Args:
        graph (nx.DiGraph): A NetworkX DiGraph.

    Returns:
        dict: A dictionary containing graph analytics.
    """

    result = dict()
    result['id'] = graph.graph['id']
    result['number_of_nodes'] = int(graph.number_of_nodes())
    result['number_of_edges'] = int(graph.number_of_edges())
    result['number_of_unique_node_labels'] = get_unique_node_labels_count(graph)
    result['number_of_unique_edge_labels'] = get_unique_edge_labels_count(graph)
    result['node_type_frequencies'] = get_node_type_frequencies(graph)
    result['edge_type_frequencies'] = get_edge_type_frequencies(graph)
    result['longest_path'] = get_longest_path(graph)

    return result

def draw_graph_graphviz(graph_tmp = None, notebook: bool = True, filename: str = "output/graph.svg", layout: str = "dot", draw_clusters: bool = True, highlight_optc_labels: bool = False, highlight_signatures_labels: bool = False):    
    """
    Draw a NetworkX MultiDiGraph using Graphviz.

    Args:
        graph_tmp (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        notebook (bool): If True, return an Image object. Default is True.
        filename (str): The output filename. Default is "output/graph.svg".
        layout (str): The layout to use. Default is "dot".
        draw_clusters (bool): If True, draw clusters. Default is True.
        highlight_optc_labels (bool): If True, highlight OPTC labels. Default is False.
        highlight_signatures_labels (bool): If True, highlight signatures labels. Default is False.
    
    Returns:
        Image: A Graphviz Image object.
    """
    
    graph = deepcopy(graph_tmp)

    # Switch attribute "image" to "process_image" -> Graphviz uses the attribute "image" to define the icon of the node
    images = nx.get_node_attributes(graph, "image")
    for key in images.keys():
        graph.nodes[key]["process_image"] = graph.nodes[key]["image"]
        del graph.nodes[key]["image"]
    
    # Replace illegal character (some libaries such as graphviz don't like backslashs)
    for node, _ in graph.nodes(data=True):
        for attribute in graph.nodes[node]:
            if type(graph.nodes[node][attribute]) == str:
                graph.nodes[node][attribute] = graph.nodes[node][attribute].replace("\\", "/")
                graph.nodes[node][attribute] = graph.nodes[node][attribute].replace("ADMINI~1", "ADMINISTRATOR")
    
    # Highlight OPTC labels
    if highlight_optc_labels:
        for edge in graph.edges(data=True):
            if edge[2]['edge_optc_label'] == 'malicious':
                graph.nodes[edge[1]]["color"] = "red"
                graph.nodes[edge[1]]["style"] = "filled"
                graph[edge[0]][edge[1]][0]['color'] = 'red'

    # Highlight signatures labels
    if highlight_signatures_labels:
        for edge in graph.edges(data=True):
            if edge[2]['edge_signature_label'] == 'intersection':
                graph.nodes[edge[0]]["color"] = "red"
                graph.nodes[edge[0]]["style"] = "filled"
                graph.nodes[edge[1]]["color"] = "red"
                graph.nodes[edge[1]]["style"] = "filled"
                graph[edge[0]][edge[1]][0]['color'] = 'red'
            elif edge[2]['edge_signature_label'] == 'sig_only':
                # Don't color the node, because it is already colored
                if 'color' not in graph.nodes[edge[0]]:
                    graph.nodes[edge[0]]["color"] = "blue"
                    graph.nodes[edge[0]]["style"] = "filled"
                if 'color' not in graph.nodes[edge[1]]:
                    graph.nodes[edge[1]]["color"] = "blue"
                    graph.nodes[edge[1]]["style"] = "filled"
                graph[edge[0]][edge[1]][0]['color'] = 'blue'
            elif edge[2]['edge_signature_label'] == 'sig2_only':
                # Don't color the node, because it is already colored
                if 'color' not in graph.nodes[edge[0]]:
                    graph.nodes[edge[0]]["color"] = "green"
                    graph.nodes[edge[0]]["style"] = "filled"
                if 'color' not in graph.nodes[edge[1]]:
                    graph.nodes[edge[1]]["color"] = "green"
                    graph.nodes[edge[1]]["style"] = "filled"
                graph[edge[0]][edge[1]][0]['color'] = 'green'
            else:
                print(edge[2]['edge_signature_label'])

    A = nx.nx_agraph.to_agraph(graph) 

    # Group nodes by its types
    if draw_clusters:    
        clusters = dict()    
        for node in A.nodes_iter():
            key = 'cluster_' +  node.attr['type']
            if key in clusters:
                clusters[key] += [node]
            else:
                clusters[key] = [node]
        for name, cluster in clusters.items():
            A.subgraph(cluster, name, label=name.replace('cluster_', ''))

    A.layout(prog=layout)
    A.draw(filename)
    
    if notebook:    
        if get_extension(filename) == "png":
            return Image(filename)
        else:
            return SVG(filename)
    else: 
        return filename
    
def get_signature(source_node, edge, target_node) -> Tuple[str, str, str, str, str]:
    """
    Get signature of edge

    Args:
        source_node (dict): The source node.
        edge (tuple): The edge.
        target_node (dict): The target node.

    Returns:
        Tuple[str, str, str, str, str]: A tuple containing the signature of the edge.
    """
    source_label = source_node['label']
    source_type = source_node['type']
    edge_type = edge[2]['edge_type']
    target_label = target_node['label']
    target_type = target_node['type']
    return (source_label, source_type, edge_type, target_label, target_type)

def get_signatures(graph: nx.Graph) -> Set[Tuple[str, str, str, str, str]]:
    """
    Get signatures of graph

    Args:
        graph (nx.Graph): A NetworkX Graph.
    
    Returns:
        Set[Tuple[str, str, str, str, str]]: A set of signatures.
    """
    signatures = list()
    for edge in graph.edges(data=True):
        signatures.append(get_signature(graph.nodes[edge[0]], edge, graph.nodes[edge[1]]))
    return set(signatures)

def signatures_to_graph(signatures: List[Tuple[str, str, str, str, str]]) -> nx.MultiDiGraph:
    """
    Create graph from signatures

    Args:
        signatures (List[Tuple[str, str, str, str, str]]): A list of signatures.

    Returns:
        nx.MultiDiGraph: A NetworkX MultiDiGraph.
    """
    graph = nx.MultiDiGraph()
    for signature in signatures:
        source_label = signature[0]
        source_type = signature[1]
        edge_type = signature[2]
        target_label = signature[3]
        target_type = signature[4]
        graph.add_edge(source_label, target_label, edge_type=edge_type, source_type=source_type, target_type=target_type)
    return graph

def signatures_to_df(signatures: List[Tuple[str, str, str, str, str]], signature_label: str) -> pd.DataFrame:
    """
    Create DataFrame from signatures

    Args:
        signatures (List[Tuple[str, str, str, str, str]]): A list of signatures.
        signature_label (str): The signature label.

    Returns:
        pd.DataFrame: A DataFrame containing signatures.
    """
    df = pd.DataFrame.from_records(signatures, columns=['source_id', 'source_type', 'edge_type', 'target_id', 'target_type'])
    df['source_label'] = df['source_id']
    df['target_label'] = df['target_id']
    df['source_id'] = df['source_id'] + '_' + df['source_type']
    df['target_id'] = df['target_id'] + '_' + df['target_type']
    df['edge_label'] = df['edge_type']
    df['edge_signature_label'] = signature_label
    
    return df
    
def merge_graphs(graph1: nx.MultiDiGraph, graph2: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """
    Merge two graphs

    Args:
        graph1 (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        graph2 (nx.MultiDiGraph): A NetworkX MultiDiGraph.
    Returns:
        nx.MultiDiGraph: A NetworkX MultiDiGraph.
    """
    sig_graph1 = get_signatures(graph1)
    sig_graph2 = get_signatures(graph2)
    
    intersection = list(set(sig_graph1) & set(sig_graph2))
    sig_graph1_only = [x for x in sig_graph1 if x not in intersection]
    sig_graph2_only = [x for x in sig_graph2 if x not in intersection]

    
    intersection_df = signatures_to_df(intersection, 'intersection')
    sig_only_df = signatures_to_df(sig_graph1_only, 'sig_only')
    sig2_only_df = signatures_to_df(sig_graph2_only, 'sig2_only')
    df = pd.concat([intersection_df, sig_only_df, sig2_only_df])
    graph = to_graph(df)
    return graph


def graph_includes_singniture_edges(signature_graph, graph, score: bool=False, details: bool=True, round_digits: int=2) -> bool:
    """
    Check if graph includes all edges of signature graph - graph can include more edges
    
    Args:
        signature_graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        score (bool): If True, return a score. Default is False.
        details (bool): If True, return details. Default is True.
        round_digits (int): The number of digits to round to. Default is 2.
    
    Returns:
        bool: True if graph includes all edges of signature graph, otherwise False.
    """
    signature_graph_edges = get_signatures(signature_graph)
    graph_edges = get_signatures(graph)
    
    included_edges = 0
    excluded_edges = 0
    for edge in graph_edges:
        if edge in signature_graph_edges:
            included_edges += 1
        else:
            excluded_edges += 1

    if score:
        return round(included_edges/len(signature_graph_edges), round_digits)
    elif details:
        return included_edges, excluded_edges

    else:
        if len(included_edges) == len(signature_graph_edges):
            return True
        else:
            return False

def get_extension(filename: str) -> str:
    """
    Get the extension of a file.

    Args:
        filename (str): The filename.

    Returns:
        str: The extension of the file.
    """
    return pathlib.Path(filename).suffix.replace(".", "")

def get_rows_containing_substring_in_column(df: pd.DataFrame, substring: str, column: str) -> pd.DataFrame:    
    """
    Get rows containing substring in column

    Args:
        df (pd.DataFrame): The input DataFrame to process.
        substring (str): The substring.
        column (str): The column.
    
    Returns:
        pd.DataFrame: A DataFrame containing rows containing substring in column.
    """
    if type(column) == list:
        rows = list()
        for c in column:
            rows.append(df.loc[df[c].str.contains(substring, case=False)])
        return pd.concat([row for row in rows])
    elif type(column) == str:
        return df.loc[df[column].str.contains(substring, case=False)]
    else:
        raise ValueError('Attribute column has to be a list or string')
    
def get_ip_from_dns_query_result(input: str) -> str:
    """
    Get IP from DNS query result

    Args:
        input (str): The input string.

    Returns:
        str: The IP if the input string is a DNS query result, otherwise None.
    """
    regex = r'^.*::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3});'
    result = re.findall(regex, input)
    if len(result) == 1:
        return result[0]
    else:
        return None
    
def get_filename(path: str, extension: bool = True) -> str:
    """
    Get the filename from a path
    :param path: path to the file
    :param extension: defines if the extension should be return or not
    """
    if extension:
        return str(ntpath.basename(path))
    else:
        return str(pathlib.Path(path).stem)
    
def parse_command_line(image: str, command: str) -> str :
    """
    Parse command line
    
    Args:
        image (str): The image.
        command (str): The command line.
    
    Returns:
        str: The parsed command line.
    """
    regex_with_extension = r"(.*?" + get_filename(image, extension=True) + ")[\"]?(.*)"
    regex_without_extension = r"(.*?" + get_filename(image, extension=False) + ")[\"]?(.*)"
    
    # Remove path and executable from the command
    result = re.findall(regex_with_extension, command)
    if result:
        parsed_command = result[0][1]
    else:
        result = re.findall(regex_without_extension, command)
        if result:
            parsed_command = result[0][1]
        else:
            parsed_command =  command

    return parsed_command

def split_ip_port(input: str) -> Tuple[str, str]:
    """
    Split IP and port from input string

    Args:
        input (str): The input string.

    Returns:
        Tuple[str, str]: A tuple containing the IP and port.
    """
    ip, _, port = input.rpartition(':')
    return ip, int(port)


def generalize_registry_key(key, segments: int=4) -> str:
    """
    Generalize registry key
    :param key key to generalize
    :param segments number of segments to use for generalization
    https://www.cyber.airbus.com/a-sysmon-bug-into-the-abbreviated-versions-of-registry-root-names/
    """
    regex = r'([A-Za-z\-0-9]+)\/?'
    result = re.findall(regex, key)
    
    if result[0] == 'hku':
        """
        HKEY_CURRENT_USER: contains configuration information for Windows and software specific to the currently logged-in user.        
        """
        summarized_key =  result[0]  + '/<user>/' + '/'.join(result[2:segments+1])
    elif result[0] in ['hklm', 'hkcr', 'registry']:
        """
        HKEY_LOCAL_MACHINE (hklm): contains settings that relate to the local computer 
        HKEY_CLASSES_ROOT: contains file name extension associations and COM class registration information such as ProgIDs, CLSIDs, and IIDs    
        """
        summarized_key =  '/'.join(result[:segments])
    else:
        print(key)
        print("not implemented")
        summarized_key = key
    return summarized_key

def generalize_registry_key_optc(key, segments: int=4) -> str:
    """
    Generalize registry key
    :param key key to generalize
    :param segments number of segments to use for generalization

    Example keys:

    """
    key = key.lower()
    regex = r'([A-Za-z\-0-9]+)\/?'
    result = re.findall(regex, key)
    if len(result) <= segments:
        segments = len(result)
    if result[1] == 'a':
        """
        User-mode applications use application hives in the registry to store app-specific state data.
        """
        #  Check for additional id (not sure if this is required)
        regex_id = r'(\{[A-Za-z\-0-9]+\})\/?'
        if len(result) > 4:
            result_id = re.findall(regex_id, result[4])
        else:
            result_id = list()
        if len(result_id) == 1:
            summarized_key =  result[0] + '/' + result[1] + '/<id>/' + result[3]
        else:
            summarized_key =  result[0] + '/' + result[1] + '/<id>/' + '/'.join(result[3:segments+1])
    elif result[1] == "user":
        summarized_key =  result[0] + '/' + result[1] + '/<user>/' + '/'.join(result[3:segments+1])
    elif result[1] == "machine":
        summarized_key =  '/'.join(result[:segments])
    else:
        print(key)
        print("not implemented")
        summarized_key = key
    return summarized_key

def generalize_registry_keys(keys: List[str], segments: int=4) -> List[str]:
    """
    Generalize multiple registry keys
    :param keys list of keys to generalize
    :param segments number of segments to use for generalization
    """
    generalized_keys = set()

    for key in keys:
        generalized_keys.add(generalize_registry_key(key, segments))

    return list(generalized_keys)

def generalize_filename(filename: str) -> str:
    """
    Generalize filename
    :param filename filename to generalize
    """
    # regex = r'.*\.([A-Za-z\-0-9]*)'
    return '<filename>.' + get_extension(filename)

def generalize_module(module: str) -> str:
    """
    Generalize module
    :param module module to generalize
    """
    return get_filename(module)

def generalize_ip(ip: str) -> str:
    """
    Generalize filename by wildcarding the ip
    :param filename filename to generalize
    """
    regex = r'^.*\:([0-9]*)'
    port = int(re.search(regex, ip).group(1))
    if port in port_mappings.keys():
        return f'<ip>:{port_mappings[port]}'
    else:
        return f'<ip>:others'

def generalize_username_in_path(ip: str) -> str:
    """
    Generalize filename by wildcarding the ip
    :param filename filename to generalize
    """
    regex = r'.*\\Users\\(.*)\\'
    result = re.findall(regex, path)
    if len(result) >= 0:
        path = path.replace(result[0], '<user>')
    return path

def generalize_payload_in_shell(payload: str) -> str:
    """
    Generalize payload by extracting the high-level command
    :param payload payload to generalize
    """
    regex = r'commandinvocation\((.*)\)'
    result = re.search(regex, payload)

    if result.group(1): 
        return result.group(1)
    else:
        return np.nan

def is_ip(input: str) -> bool:
    try:
        ipaddress.ip_address(input)
        return True
    except Exception as e:
        return False
    
class Url():
    def __init__(self, subdomain: str = None, domain: str = None, tld: str = None, scheme: str = None, path: str = None, query: str = None, fragment: str = None, ip: str = None, port: str = None, username: str = None, password: str = None):
        self.subdomain = None if subdomain == "" else subdomain
        self.domain = None if domain == "" else domain
        self.tld = None if tld == "" else tld
        self.scheme = None if scheme == "" else scheme
        self.path = None if path == "" else path
        self.query = None if query == "" else query
        self.fragment = None if fragment == "" else fragment
        self.ip = None if ip == "" else ip
        self.port = None if port == "" else port
        self.username = None if username == "" else username
        self.password = None if password == "" else password
    
    @staticmethod
    def from_string(input: str):
        
        url = Url()
        res = urlparse(input)
            
        url.scheme=res.scheme
        url.path=res.path
        url.query=res.query
        url.fragment=res.fragment
        url.port=res.port
        url.username=res.username
        url.password=res.password

        ip = res.netloc.replace(f":{res.port}", "")
        if is_ip(ip):
            url.ip = ip

        tld = get_tld(input, as_object=True, fail_silently=True, fix_protocol=True)

        if tld:
            url.subdomain = None if tld.subdomain == "" else tld.subdomain
            url.domain = None if tld.domain == "" else tld.domain
            url.tld = None if tld.tld == "" else tld.tld     

        return url
    
    def get_root_url(self) -> str:
        if self.domain and self.tld:
            return self.domain + "." + self.tld
        else:
            return "invalid_url"
    
    def __eq__(self, other) : 
        return self.__dict__ == other.__dict__

def generalize_command_line(command: str) -> str:
    """
    Generalize command line

    Args:
        command (str): The command line.

    Returns:
        str: The generalized command line.
    """
    # Check if url or file in path
    regex_urls_files = r".*[\'\"](.*)[\'\"].*"
    result = re.findall(regex_urls_files, command)
    if result:
        url = Url.from_string(result[0])
        if url.scheme in ['http', 'https', 'ssh', 'ftp']:
            command = command.replace(result[0], url.scheme + '://<url>/' + '<file>.' + get_extension(url.path) if get_extension(url.path) else '')
        else:
            command = command.replace(result[0], '<file>.' + get_extension(url.path))
    
    # Check for process guids
    regex_guids = r"^.*([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}).*"
    result = re.findall(regex_guids, command)
    if result:
        command = command.replace(result[0], '<guid>')

    return command

def get_rows_with_duplicated_column_values(df: pd.DataFrame, columns: list = None) -> pd.DataFrame:
    """
    Get rows with duplicated column values

    Args:
        df (pd.DataFrame): The input DataFrame to process.
        columns (list): The columns. Default is None.

    Returns:
        pd.DataFrame: A DataFrame containing rows with duplicated column values.
    """
    if type(columns) == list:
        if all(elem in df.columns for elem in columns):
            return df[df.duplicated(subset=columns, keep=False) == True]
        raise ValueError(f"Columns [{columns}] is not in dataframe")
    elif type(columns) == str:
        if columns in df.columns:
            return df[df.duplicated(subset=[columns], keep=False) == True]
        else:
            raise ValueError(f"Column {columns} is not in dataframe")
    else:
        raise TypeError(f"Columns must be a list or string, not {type(columns)}")


def filter_by_edge_property(graph: nx.MultiDiGraph, property: str, value: str, keep_process_chain: bool = True, node_filters: list = None):
    """
    Filter graph by edge property
    
    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        property (str): The property.
        value (str): The value.
        keep_process_chain (bool): If True, keep the process chain. Default is True.
        node_filters (list): The node filters. Default is None.
    
    Returns:
        nx.MultiDiGraph: A filtered NetworkX MultiDiGraph.
    """
    if type(value) == str:
        edges = [(u,v) for u,v,e in graph.edges.data() if e[property] == value]
    else:
        edges = [(u,v) for u,v,e in graph.edges.data() if e[property] in value]

    nodes = set()
    for source, target in edges:
        if node_filters:
            if graph.nodes[target]['type'] in node_filters:
                nodes.add(source)
                nodes.add(target)
        else:
            nodes.add(source)
            nodes.add(target)
    if keep_process_chain:
        for node in graph.nodes(data=True):
            if node[1]['type'] == 'PROCESS':
                nodes.add(node[0])

    subgraph = graph.subgraph(nodes).copy()

    return subgraph

def prettify_edge_labels(graph, include_edge_feature: bool = True, optc: bool=True):
    """
    Add the edge type to the label
    
    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        include_edge_feature (bool): If True, include the edge feature. Default is True.
        optc (bool): If True, include the OPTC label. Default is True.
    
    Returns:
        nx.MultiDiGraph: A NetworkX MultiDiGraph with prettified edge labels.
    """
    tmp_graph = graph.copy()
    for u, v, key in graph.edges(keys=True):
        # Depending on graph type
        if include_edge_feature:
            if isinstance(tmp_graph[u][v][key]['edge_feature'], int):
                tmp_graph[u][v][key]['edge_feature'] = sum(tmp_graph[u][v][key]['edge_feature'])
            else:
                tmp_graph[u][v][key]['edge_feature'] = len(tmp_graph[u][v][key]['edge_feature'])
            tmp_graph[u][v][key]['label'] = tmp_graph[u][v][key]['edge_type'].split('_')[1].lower() + ' [' + str(tmp_graph[u][v][key]['edge_feature']) + ']'
        else:
            if optc:
                tmp_graph[u][v][key]['label'] = tmp_graph[u][v][key]['edge_type'].split('_')[1].lower()
            else:
                # Remove past tense
                try:
                    tmp_graph[u][v][key]['label'] = tmp_graph[u][v][key]['edge_type'].split('_')[0].lower()[:-1]
                except:
                    tmp_graph[u][v][key]['label'] = tmp_graph[u][v][key]['edge_type'].lower()[:-1]
    
    return tmp_graph

def prettify_node_labels(graph) -> nx.MultiDiGraph:
    """
    Add the node type to the label

    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.

    Returns:
        nx.MultiDiGraph: A NetworkX MultiDiGraph with prettified node labels.
    """
    tmp_graph = graph.copy()
    for node in tmp_graph.nodes:
        node_type = tmp_graph.nodes[node]['type']
        # Make sandbox results consistent with our data model
        if node_type == 'HOST':
            node_type = 'FLOW'
        elif node_type == 'KEY':
            node_type = 'REGISTRY'            
        tmp_graph.nodes[node]['label'] = tmp_graph.nodes[node]['label'] + '\n:' + tmp_graph.nodes[node]['type'].title()
    return tmp_graph

def prettify_graph(graph, include_edge_feature: bool = True, optc: bool=True) -> nx.MultiDiGraph:
    """
    Prettify graph

    Args:
        graph (nx.MultiDiGraph): A NetworkX MultiDiGraph.
        include_edge_feature (bool): If True, include the edge feature. Default is True.
        optc (bool): If True, include the OPTC label. Default is True.

    Returns:
        nx.MultiDiGraph: A NetworkX MultiDiGraph with prettified labels.
    """
    tmp_graph = prettify_edge_labels(graph, include_edge_feature=include_edge_feature, optc=optc)
    tmp_graph = prettify_node_labels(tmp_graph)
    return tmp_graph

def get_differential_graph(df: pd.DataFrame, id1: int, id2: int, generalization: Generalization = Generalization.BEHAVIOURAL, node_filters: List[NodeType] = None)-> nx.DiGraph: 
    """
    Get a differential graph from two experiments

    Args:
        df (pd.DataFrame): Dataframe containing the experiment results
        id1 (int): ID of the first experiment
        id2 (int): ID of the second experiment
        notebook (bool, optional): Whether to draw the graph in a notebook. Defaults to True.
        filename (str, optional): Filename of the output graph. Defaults to "output/graph.svg".
    
    Returns:
        graph (nx.DiGraph): Differential graph
    """
    process_centric_graph1 = get_experiment_graph(df, id1, generalization=generalization)
    process_centric_graph2 = get_experiment_graph(df, id2, generalization=generalization)
    graph = merge_graphs(process_centric_graph1, process_centric_graph2)
    node_filters = [node.name for node in node_filters]
    graph_unique = filter_by_edge_property(graph, 'edge_signature_label', ['sig_only', 'sig2_only'], node_filters=node_filters)
    graph_unique = prettify_graph(graph_unique, include_edge_feature=False, optc=False)
    return graph_unique

def draw_differential_graph(df: pd.DataFrame, id1: int, id2: int, node_filters: List[NodeType] = None, notebook: bool = True, filename: str = "output/graph.svg")-> str:
    """
    Draw a differential graph from two experiments

    Args:
        df (pd.DataFrame): Dataframe containing the experiment results
        id1 (int): ID of the first experiment
        id2 (int): ID of the second experiment
        notebook (bool, optional): Whether to draw the graph in a notebook. Defaults to True.
        filename (str, optional): Filename of the output graph. Defaults to "output/graph.svg".
    
    Returns:
        str: Path to the output graph
    """
    graph = get_differential_graph(df, id1, id2, node_filters=node_filters, notebook=notebook, filename=filename)
    return draw_graph_graphviz(graph, notebook=notebook, filename=filename, draw_clusters=True, highlight_signatures_labels=True)

def get_experiment_graph(df: pd.DataFrame, id: int, generalization: Generalization = Generalization.BEHAVIOURAL,  ignore_first_hop: bool = False) -> nx.MultiDiGraph:
    """
    Get the process centric graph of an experiment

    Args:
        df (pd.DataFrame): Dataframe containing the experiment results
        id (int): ID of the experiment
        ignore_first_hop (bool, optional): Whether to ignore the first hop of the graph. Defaults to False.
    
    Returns:
        process_centric_graph1 (nx.MultiDiGraph): Process centric graph of the experiment
    """
    df = df.reset_index().copy()
    df1 = pd.read_pickle(df[df['id'] == id ]['graph_df_path'][np.NaN].tolist()[0])


    if generalization == Generalization.BEHAVIOURAL:
        df_generalized = behavioural_generalization(df1, keep_process_chain=False, optc=False)
    elif generalization == Generalization.STRUCTURAL:
        df_generalized = structural_generalization(df1, keep_process_chain=False, optc=False)
    else:
        df_generalized = df1.copy()

    identifiers1 = get_node_of_interest_identifiers(df1, df[df['id'] == id ]['filename'][np.NaN].tolist()[0], df[df['id'] == id ]['executable'][np.NaN].tolist()[0])
    graph1 = to_graph(df_generalized)
    process_centric_graph1 = filter_by_node_identifiers(graph1, identifiers1, ancestors=False, ignore_first_hop=ignore_first_hop)
    return process_centric_graph1

def draw_experiment_graph(df: pd.DataFrame, id: int, generalization: Generalization = Generalization.BEHAVIOURAL,  ignore_first_hop: bool = False) -> str:
    """
    Draw the process centric graph of an experiment

    Args:
        df (pd.DataFrame): Dataframe containing the experiment results
        id (int): ID of the experiment

    Returns:
        str: Path to the output graph
    """
    process_centric_graph1 = get_experiment_graph(df, id, generalization=generalization, ignore_first_hop=ignore_first_hop)
    return draw_graph_graphviz(process_centric_graph1, draw_clusters=False, highlight_signatures_labels=False)