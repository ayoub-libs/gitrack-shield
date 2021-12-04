#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import
import shutil
import sys
import datetime
import argparse
import hashlib
import tempfile
import os
import re
import json
import logging
import git
from git import Repo
from git import NULL_TREE
from utils import *

logging.basicConfig(format='%(message)s', level=logging.INFO)

yaml_kp = ["API_KEY_GENERAL", "N00NPAY_KEY", "SERVICES_SECRET", "PASSWORD", "PROJECT_API_KEY", "JWT_3DS", 
           "SENDGRID_KEY", "ZENDESK_TOKENS", "BRAZE_API_KEY", "BRAZE_S3", "KEY_BRAZE_CAMPAIGN"]

special_paths_inclusion = {
    "SERVICE_ACCOUNT": ".*\.json",
    "three_DS_key": ".*\.(yaml|yml|py)"
}

for kp in yaml_kp:
    special_paths_inclusion[kp] = ".*\.(yaml|yml)"

def args_parsing():
    parser = argparse.ArgumentParser(description='Finding secrets in Github code ..')
    parser.add_argument('file_path', type=str, help='Local repository path')
#    parser.add_argument('--base-branch', dest="base_branch", nargs='?', type=str, help='Scan a specific branch')
    parser.add_argument('-b', '--head-branch', dest="branch", nargs='+', type=str, help='Scan the main branch')
    parser.add_argument('-t', '--secret-type', dest="secret_type", nargs='+', help= 'provide a list of scanning types, ex: --secret-type service_account DB_pwd (from special_paths_inclusion list)')
    parser.add_argument('-r', '--rules-file', dest="rules_file", type=str, help= 'The path to the regex rules file')
    parser.add_argument('-f', '--false-positive', dest="false_positive", type=str, help="Excluding false positives")
    return parser

def main():

    global rules
    global pattern_exclusions

    pattern_exclusions = []
    args = args_parsing().parse_args()

    false_positive = args.false_positive
    rules_file = args.rules_file if args.rules_file else '{}/../../gitrack-shield/configs/secrets-service.json'.format(args.file_path)
    if not os.path.exists(os.path.abspath(rules_file)):
        rules_file = "gitrack-shield/secrets-service.json"
    try:
        with open(rules_file, "r") as ruleFile:
            rules = json.loads(ruleFile.read())

        for rule in rules:
            rules[rule] = re.compile(rules[rule], flags=re.MULTILINE)

    except (IOError, ValueError) as e:
        raise("Error reading rules file")


    try:
        if false_positive:
            with open(false_positive, "r") as exclusions:
                fp = [x.rstrip() for x in exclusions.readlines()]
                pattern_exclusions.extend(fp)
                pattern_exclusions = list(filter(None, pattern_exclusions))
           for item in pattern_exclusions:
                assert len(item) > 7, 'Invalid excluded patterns'
    except FileNotFoundError as f:
        logging.info("Incorrect false positive file .. skipping")

    results = git_search(args.file_path, args.branch)
    project_path = results["project_path"]
    if results["issues_results"]:
        sys.exit(1)
    else:
        sys.exit(0)


def diff_process(diff, this_commit, last_commit, branch_name, commit_hash):
    issues = []
    include_paths = []
    false_positive = None
    args = args_parsing().parse_args()
    scan_types = args.secret_type
    regexes = rules
    for rule in rules:
        if not rule in special_paths_inclusion.keys() or not special_paths_inclusion[rule]:
            special_paths_inclusion[rule] = '.*'
        include_paths.append(re.compile(special_paths_inclusion[rule]))

    if scan_types:
        include_paths.clear()
        for regex in dict(regexes):
            del regexes[regex]
        for scans in scan_types:
            for rule in rules:
                if rule == scans:
                    regexes[rule] = rules[rule]
            if rule in special_paths_inclusion.keys() and special_paths_inclusion[scans]:
                include_paths.append(re.compile(special_paths_inclusion[scans]))

    for blob in diff:
        raw_diff = blob.diff.decode('utf-8', errors='replace')
        if raw_diff.startswith("Binary files"):
            continue
        if not path_included(blob, include_paths):
            continue
        commit_time =  datetime.datetime.fromtimestamp(last_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        if commit_time < '2020-06-01':
            continue
        issues_results = []
        regex_matches = []
        skip = 0
        for key in regexes:
            leak_results = regexes[key].findall(raw_diff)
            for found_string in leak_results:
                for pattern in pattern_exclusions:
                    if pattern in found_string:
                        skip = 1
                if skip == 1:
                    continue
                diff_results = raw_diff.replace(raw_diff, bcolors.WARNING + found_string + bcolors.ENDC)
                if leak_results:
                    regex_results = {}
                    regex_results['date'] = commit_time
                    regex_results['path'] = blob.b_path if blob.b_path else blob.a_path
                    regex_results['branch'] = branch_name
                    regex_results['diff'] = blob.diff.decode('utf-8', errors='replace')
                    regex_results['stringsFound'] = leak_results
                    regex_results['printDiff'] = diff_results
                    regex_results['reason'] = key
                    regex_results['commit_hash'] = last_commit.hexsha
                    if regex_results['path'] and 'invalid_credentials.json' in regex_results['path']:
                        continue
                    regex_matches.append(regex_results)
        issues_results += regex_matches

        for issue_results in issues_results:
            if false_positive:
                continue
            print_results(issue_results)
        issues += issues_results
    return issues



def git_search(file_path, branch=None):
    results = {"issues_results": []}
    project_path = file_path
    repo = Repo(project_path)
    already_searched = set()
    results_dir = tempfile.mkdtemp()

    if branch:
        try:
            branches = repo.remotes.origin.fetch(branch)
        except git.exc.GitCommandError as g:
            print("Error in branch {} - branch removed or doesn't exist".format(branch))
            sys.exit(0)
    else:
        branches = repo.remotes.origin.fetch()

    for remote_branch in branches:
        branch_name = remote_branch.name
        branch_name_plain = branch_name
        if branch:
            branch_name_plain = branch
        last_commit = None
        for this_commit in repo.iter_commits(branch_name, max_count=100):
            commit_hash = this_commit.hexsha
            diff_hash = hashlib.md5((str(last_commit) + str(this_commit)).encode('utf-8')).digest()
            if not last_commit:
                last_commit = this_commit
                continue
            elif diff_hash in already_searched:
                last_commit = this_commit
                continue
            else:
                diff = last_commit.diff(this_commit, create_patch=True)
            already_searched.add(diff_hash)
            issues_results = diff_process(diff, this_commit, last_commit, branch_name_plain, commit_hash)
            results = return_results(results, results_dir, issues_results)
            last_commit = this_commit
        diff = this_commit.diff(NULL_TREE, create_patch=True)
        issues_results = diff_process(diff, this_commit, last_commit, branch_name_plain, commit_hash)
        results = return_results(results, results_dir, issues_results)
    results["project_path"] = project_path
    results["issues_path"] = results_dir
    return results


if __name__ == "__main__":
    main()
