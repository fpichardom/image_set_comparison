#!/usr/bin/env python3

import argparse
import os
from pathlib import Path
import paramiko
from typing import List, Dict, Tuple, Optional, Set
import logging
import json
from datetime import datetime
import yaml
import argcomplete
import sys

ImageSet = Dict[str, str]
OrphanSet = List[str]

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare local image sets with remote server.")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("local_path",nargs='?', help="Path to the local project directory")
    parser.add_argument("-H","--host", help="Remote server hostname")
    parser.add_argument("-u","--user", help="Remote server username")
    parser.add_argument("-p","--password", help="Remote server password")
    parser.add_argument("-k", "--key-file", help="Path to the SSH private key file")
    parser.add_argument("-f", "--file-type-path", action='append', nargs=2, metavar=('TYPE', 'PATH'),
                         help= "Specify a file type and its remote path. Can be used multiple times.")
    parser.add_argument("-o","--output", default=".", help="Output directory for result files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument("--thumbnail-suffix", default="-thumbnails", help="Suffix for thumbnail files")
    parser.add_argument("--valid-extensions", nargs='+', default=['.dng','.jpg'], help="List of valid file extensions")
    argcomplete.autocomplete(parser)
    
    args = parser.parse_args()

    if args.config is None and args.local_path is None:
        parser.error("Either --config or local_path must be provided")

    return args



def load_config(config_path: str) -> Dict:
    try:
        with open(config_path, 'r') as config_file:
            return yaml.safe_load(config_file)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"Error reading config file: {e}", file=sys.stderr)
        sys.exit(1)

def setup_logging(verbose: bool, output_dir: str) -> None:
    
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename: str = os.path.join(output_dir, f"image_comparison_{timestamp}.log")
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig( level=level,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler(log_filename),
                            logging.StreamHandler()
                        ]) #filename=log_filename,
    #console: logging.StreamHandler = logging.StreamHandler()
    #console.setLevel(level)
    #logging.getLogger('').addHandler(console)

def get_file_type(filename:str, valid_extensions: Set[str], thumbnail_suffix: str) -> Tuple[str, str]:
    name, ext = os.path.splitext(filename)
    ext: str = ext.lower() # Convert extension to lowercase for case-insensitive comparison

    if ext in valid_extensions:
        if name.lower().endswith(thumbnail_suffix.lower()):
            return name[:-len(thumbnail_suffix)], 'thumbnail'
        return name, ext[1:] # Remobe the dot from the extension
    return name, '' # Return empty string for the file type if extension is not recognized

def find_local_image_sets(root_dir: str, valid_extensions: Set[str], thumbnail_suffix: str) -> Tuple[Dict[str, ImageSet], Dict[str, OrphanSet]]:
    image_sets: Dict[str, Dict[str, str]] = {}
    
    orphans: Dict[str, List[str]] = {}

    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            base_name, file_type = get_file_type(filename, valid_extensions, thumbnail_suffix)

            if not file_type:
                continue # Skip files that are not recognized types

            image_sets.setdefault(base_name, {})[file_type] = full_path

            #if base_name not in image_sets: # Is is not part of the keys
            #    image_sets[base_name] = {}
            #image_sets[base_name][file_type] = full_path

    required_types = set(ext[1:] for ext in valid_extensions) | {'thumbnail'}
    complete_sets = {name: paths for name, paths in image_sets.items() if set(paths) == required_types}
    orphans = {name: list(paths.values()) for name, paths in image_sets.items() if set(paths) != required_types}

    # Separate complete sets and orphans
    #complete_sets: Dict[str, ImageSet] = {}
    #required_types = {'dng', 'jpg', 'thumbnail'}
    #for name, paths in image_sets.items():
    #    if set(paths) == required_types:
    #        complete_sets[name] = paths
    #    else:
    #        orphans[name] = list(paths.values())

    return complete_sets, orphans

def check_remote_image_sets(
        ssh_client: paramiko.SSHClient,
        local_sets: Dict[str, ImageSet],
        remote_paths:Dict[str, List[str]],
        #thumbnail_suffix: str
) -> Dict[str, ImageSet]:
    
    remote_status: Dict[str, ImageSet] = {}

    for name, local_paths in local_sets.items():
        remote_paths_found: ImageSet = {}
        required_file_types: Set[str] = set(local_paths)
        
        #for file_type, local_path in local_paths.items():
        for file_type in required_file_types:
            local_path: str = local_paths[file_type]
            file_name: str = os.path.basename(local_path)
            #if file_type == 'thumbnail':
            #    file_name = f"{name}{thumbnail_suffix}{os.path.splitext(filename)[1]}"
            for remote_base_path in remote_paths.get(file_type, []):
                full_remote_path: str = os.path.join(remote_base_path, file_name)
                if check_remote_file_exists(ssh_client, full_remote_path):
                    remote_paths_found[file_type] = full_remote_path
                    break

        if set(remote_paths_found) == required_file_types:
            remote_status[name] = remote_paths_found
        else:
            missing_types: Set[str] = required_file_types - set(remote_paths_found)
            logging.debug(f"Image set {name} is incomplete on remote. Missing types: {missing_types}")
    return remote_status
        

def check_remote_file_exists(ssh_client: paramiko.SSHClient, remote_path: str) -> bool:
    try:
        with ssh_client.open_sftp() as sftp:
            sftp: paramiko.SFTPClient
            try:
                sftp.stat(remote_path)
                return True
            except FileNotFoundError:
                return False
    except Exception as e:
        logging.error(f"Error checking remote file {remote_path}: {str(e)}")
        return False
    #sftp: paramiko.SFTPClient = ssh_client.open_sftp()
    #try:
    #    sftp.stat(remote_path)
    #    return True
    #except FileNotFoundError:
    #    return False
    #finally:
    #    sftp.close()

def connect_ssh(host: str, username: str, password: Optional[str] = None, key_file: Optional[str] = None) -> paramiko.SSHClient:
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        if key_file:
            #key = paramiko.RSAKey.from_private_key_file(key_file)
            #ssh_client.connect(host, username=username, pkey=key)
            ssh_client.connect(host, username=username, key_filename=key_file)
        elif password:
            ssh_client.connect(host, username=username, password=password)
        else:
            raise ValueError("Either password or key_file must be provided")
    except Exception as e:
        logging.error(f"Failed to connect to {host}: {str(e)}")
        raise

    return ssh_client

def write_json_file(data: Dict, filename: str) -> None:
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)



def main() -> None:
    args = parse_arguments()

    if args.config:
        try:
            config= load_config(args.config)
            output_dir = config.get('output') or args.output
            verbose = config.get('verbose', False)
            setup_logging(verbose, output_dir)

            logging.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logging.error(f"Failed to load config file: {e}")
            raise ValueError(f"Error loading config file: {e}")
    
        local_path = config.get('local_path') or args.local_path
        host = config.get('host')
        user = config.get('user')
        password = config.get('password')
        key_file = config.get('key_file')
        file_type_paths = config.get('file_type_path', {})


        thumbnail_suffix = config.get('thumbnail_suffix','-thumbnails')
        valid_extensions = set(config.get('valid_extensions', ['.dng', '.jpg']))
    else:
        
        setup_logging(args.verbose, args.output)

        local_path = args.local_path
        host = args.host
        user = args.user
        password = args.password
        key_file = args.key_file
        file_type_paths = {ft: [path] for ft, path in args.file_type_path} if args.file_type_path else {}
        output_dir = args.output
        verbose = args.verbose
        thumbnail_suffix = args.thumbnail_suffix
        valid_extensions = set(args.valid_extensions)
    
    # Setup logging after we've determined the output directory and verbose setting
    setup_logging(verbose, output_dir)

    logging.info("Starting image set comparison")
    logging.debug("Configuration:")
    logging.debug(f"local_path: {local_path}")
    logging.debug(f"host: {host}")
    logging.debug(f"user: {user}")
    logging.debug(f"key_file: {key_file}")
    logging.debug(f"file_type_path: {file_type_paths}")
    logging.debug(f"output_dir: {output_dir}")
    logging.debug(f"verbose: {verbose}")
    logging.debug(f"thumbnail_suffix: {thumbnail_suffix}")
    logging.debug(f"valid_extensions: {valid_extensions}")



    if not local_path:
        print("Error: local_path must be provided either in the config file or as an argument", file=sys.stderr)
        sys.exit(1)

    if not all([local_path, host, user, file_type_paths]):
        missing = []
        if not local_path: missing.append("local_path")
        if not host: missing.append("host")
        if not user: missing.append("user")
        if not file_type_paths: missing.append("file_type_path")
        raise ValueError(f"Missing required arguments: {', '.join(missing)}. "
                         "Provide either a config file or all required command-line arguments.")

    logging.info(f"Using thumbnail suffix: {thumbnail_suffix}")
    logging.info(f"Valid extensions: {valid_extensions}")

    logging.info(f"Starting image set comparison for local path: {local_path}")
    local_sets, orphans = find_local_image_sets(local_path, valid_extensions, thumbnail_suffix)
    logging.info(f"Found {len(local_sets)} complete local image sets and {len(orphans)} orphaned images")

    write_json_file(local_sets, os.path.join(output_dir, "complete_local_sets.json"))
    write_json_file(orphans, os.path.join(output_dir, "local_orphans.json"))

    try:
        logging.info(f"Connecting to remote server: {host}")
        ssh_client = connect_ssh(host, user, password, key_file)

        logging.info(f"Checking remote server for matching image sets")
        remote_status = check_remote_image_sets(ssh_client, local_sets, file_type_paths) # thumbnail_suffix

        write_json_file(remote_status, os.path.join(output_dir, "matched_remote_sets.json"))

        logging.info("/nComparison Results:")
        for name in local_sets:
            status = "exists" if name in remote_status else "missing"
            logging.info(f"{name}: {status} on remote server")

        missing_count = len(local_sets) - len(remote_status)
        logging.info(f"\nTotal missing sets on remote server: {missing_count}")

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        print(f"An error occurred: {str(e)}")
    finally:
        if 'ssh_client' in locals():
            ssh_client.close()


if __name__ == "__main__":
    main()

