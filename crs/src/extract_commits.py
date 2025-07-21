import os
import git
from datetime import datetime
import subprocess
import pwd
import grp
import yaml


def extract_commits(repo_path, output_directory):
    # Ensure the output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Initialize the repo object
    repo = git.Repo(repo_path)

    # Iterate over each commit in the repository
    commits = list(repo.iter_commits())
    for commit in commits[0:-1]:  # Skips the first commit
        # Format the filename with commit date and hash
        date_str = datetime.fromtimestamp(commit.committed_date).strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"{date_str}_{commit.hexsha}.txt"
        file_path = os.path.join(output_directory, filename)

        # Write commit details and diff to the file
        with open(file_path, 'w') as file:
            file.write(f"Commit: {commit.hexsha}\n")
            file.write(f"Author: {commit.author.name} <{commit.author.email}>\n")
            file.write(f"Date: {date_str}\n\n")
            file.write(f"Message: {commit.message}\n")
            file.write("----\n\n")
            # Getting the output of `git show` for the commit
            show_output = repo.git.show(commit.hexsha, pretty='format:')
            file.write(show_output)

def get_current_user_and_group():
    # Get the current user's ID
    uid = os.getuid()
    # Get the current user's username
    user_info = pwd.getpwuid(uid)
    username = user_info.pw_name
    # Get the current user's primary group ID
    gid = user_info.pw_gid
    # Get the current user's primary group name
    group_info = grp.getgrgid(gid)
    groupname = group_info.gr_name
    return username, groupname

def change_ownership_and_permissions(directory, user, group):
    try:
        # Change ownership
        subprocess.run(['chown', '-R', f'{user}:{group}', directory], check=True)
        print(f"Ownership changed to {user}:{group} for {directory}")
        
        # Change permissions
        subprocess.run(['chmod', '-R', '755', directory], check=True)
        print(f"Permissions changed to 755 for {directory}")
        
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while changing ownership or permissions: {e}")

def extract_commits_gpt4o(repo_path, output_directory, commits_file_name):
    # Ensure the output directory exists
    os.makedirs(output_directory, exist_ok=True)

    def process_repository(repo, output_directory, commits_file, processed_commits):
        # Iterate over each commit in the repository
        commits = list(repo.iter_commits())
        if len(commits) > 1:
            commits = commits[:-1]  # Skip the oldest commit
        else:
            return

        for commit in commits: 
            # Skip the commit if it has already been processed
            if commit.hexsha in processed_commits:
                return

            # Format the filename with commit hash
            filename = f"{commit.hexsha}.txt"
            file_path = os.path.join(output_directory, filename)

            # Write commit details and diff to the file
            with open(file_path, 'w', encoding='utf-8', errors='replace') as file:
                file.write(f"Commit: {commit.hexsha}\n")
                file.write(f"Author: {commit.author.name} <{commit.author.email}>\n")
                file.write(f"Date: {datetime.fromtimestamp(commit.committed_date).strftime('%Y-%m-%d_%H-%M-%S')}\n\n")
                file.write(f"Message: {commit.message}\n")
                file.write("----\n\n")
                # Getting the output of `git show` for the commit
                show_output = repo.git.show(commit.hexsha, pretty='format:')
                file.write(show_output)

                # Write commit ID to the commits file
                commits_file.write(f"{commit.hexsha}.txt\n")
                processed_commits.add(commit.hexsha)


    # File to store all commit IDs
    commits_file_path = os.path.join(output_directory, commits_file_name)
    processed_commits = set()  # Set to store processed commit IDs

    with open(commits_file_path, 'w', encoding='utf-8', errors='replace') as commits_file:
    
        try:
            # Initialize the repo object for the main repository
            user, group = get_current_user_and_group()
            change_ownership_and_permissions(repo_path,user,group)
            subprocess.run(["git", "config", "--add", "safe.directory", repo_path])

            main_repo = git.Repo(repo_path)
            # Process the main repository
            process_repository(main_repo, output_directory, commits_file,processed_commits)

            # Process each submodule
            for submodule in main_repo.submodules:
                submodule.update(init=True)  # Ensure the submodule is initialized and updated
                submodule_repo = submodule.module()
                process_repository(submodule_repo, output_directory, commits_file,processed_commits)

        except git.exc.InvalidGitRepositoryError:
            # Process each sub-repository in subfolders
            for root, dirs, files in os.walk(repo_path):
                if dirs == '.git' or len(dirs) > 5:
                    print(f"Skipping directory {root} because it has more than 5 subdirectories.")
                    break
                for dir in dirs:
                    sub_repo_path = os.path.join(root, dir)
                    try:
                        user, group = get_current_user_and_group()
                        change_ownership_and_permissions(sub_repo_path,user,group)
                        subprocess.run(["git", "config", "--add", "safe.directory", sub_repo_path])
                        sub_repo = git.Repo(sub_repo_path)
                        process_repository(sub_repo, output_directory, commits_file, processed_commits)
                    except git.exc.InvalidGitRepositoryError:
                        continue

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        #print("Usage: python script.py <repo_path> <output_directory>")
        repo_path = 'src/'
        output_directory = '.'
    else:
        repo_path = sys.argv[1]
        output_directory = sys.argv[2]

    all_commits_file = 'commits.txt'
    # Load the project.yaml file
    with open('project.yaml', 'r') as file:
        project_yaml = yaml.safe_load(file)

    cp_sources = project_yaml.get('cp_sources', {})
    for source_name, details in cp_sources.items():
        repo_path_source = os.path.join(repo_path, source_name)
        extract_commits_gpt4o(repo_path_source, output_directory,all_commits_file)
    
    #print all commits
    file_path = os.path.join(output_directory, all_commits_file)
    with open(file_path, 'r') as file:
        commits_content = file.read()
        commits = commits_content.strip().split('\n')
        number_of_commits = len(commits)
        print(f"number_of_commits: {number_of_commits}\n{commits_content}")
