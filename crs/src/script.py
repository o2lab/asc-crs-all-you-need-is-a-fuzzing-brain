import os
import time
import requests
import base64
import tempfile
import subprocess
import yaml
import json
import shutil
import concurrent.futures
import multiprocessing
from check_cores import get_cpu_cores_via_cgroups

# Run script0.py for debug
# if False:
#     command = ['python3', 'script0.py']
#     try:
#         result = subprocess.run(command, check=True, capture_output=True, text=True)
#         output = result.stdout + result.stderr
#     except subprocess.CalledProcessError as e:
#         output = e.stdout + e.stderr
#     except Exception as e:
#         output = str(e)
#     print(output)

# Define constants
CAPI_HOSTNAME = os.getenv('AIXCC_API_HOSTNAME')
AUTH = ('00000000-0000-0000-0000-000000000000', 'secret')

# Function to make cAPI request
def make_request(method, endpoint, data=None):
    url = f"{CAPI_HOSTNAME}/{endpoint}"
    response = requests.request(method, url, auth=AUTH, json=data)
    return response.json()

def build_initial_project() -> bool:
    command = ['./run.sh', '-x', 'build']
    # this may take a while
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
        return True, output
    except subprocess.CalledProcessError as e:
        output = e.stdout + e.stderr
    except Exception as e:
        output = str(e)

    return False, output

def execute_script(script_name):
    """
    Executes a Python script and returns its output.

    Args:
        script_name (str): The name of the Python script to execute.

    Returns:
        tuple: A tuple containing a boolean indicating success or failure, 
               the standard output, and the standard error.
    """
    command = ['python3', script_name]
    
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return True, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr
    except Exception as e:
        return False, '', str(e)

# Check if cAPI is available
print("The following CRS is developed by team 'all-you-need-is-a-fuzzing-brain'.")
for _ in range(12):
    try:
        if requests.get(f"{CAPI_HOSTNAME}/health/", auth=AUTH).ok:
            break
    except requests.ConnectionError:
        pass
    print("Waiting for the cAPI to be available...")
    time.sleep(5)
else:
    exit(1)

print("Let's run a cAPI health check before we get started.\n")
print(json.dumps(make_request('GET', 'health/'), indent=2))

CRS_HOSTNAME = os.getenv('HOSTNAME')
CRS_SCRATCH_SPACE = os.getenv('AIXCC_CRS_SCRATCH_SPACE')
dest = CRS_SCRATCH_SPACE+"/"+CRS_HOSTNAME+"/"
CP_ROOT = os.getenv('AIXCC_CP_ROOT')
# Copy CPs to scratch space
print("First, let's copy all CPs and code files scratch space.\n")
for cp in os.listdir(CP_ROOT):
    src = os.path.join(CP_ROOT, cp)
    print(f"CP: {src}")
    if src.startswith("."):
        print(f"skip non-cp: {src}")
        continue
    subprocess.run(['rsync', '--archive', '--delete', src, dest])
    cp_path = os.path.join(dest, cp)
    # Copy extract_commits.py and test_litellm.py to cp_path
    if os.path.isdir(cp_path):
        shutil.copy('extract_commits.py', cp_path)
        shutil.copy('test_litellm.py', cp_path)
        shutil.copy('sample_linux.bin', cp_path)
        shutil.copy('sample_jenkins.bin', cp_path)
        shutil.copy('sample_mock1.bin', cp_path)
        shutil.copy('sample_mock2.bin', cp_path)
        shutil.copy('sample_nginx.bin', cp_path)

# Change to CP folder
print(f"\ndest: {dest}")
cp_dirs = [d for d in os.listdir(dest) if os.path.isdir(os.path.join(dest, d))]
print(f"cp_dirs: {cp_dirs}")

total_timeout = 4 * 60 * 60
# test for 5 mins
# total_timeout = 5 * 60

ITERATION = 1
def run_test_litellm_internal(commit_file):
    global ITERATION
    print(f"crs iteration {ITERATION} for {commit_file}")
    command = ['python3', 'test_litellm.py', commit_file]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
    except subprocess.CalledProcessError as e:
        output = e.stdout + e.stderr
    except Exception as e:
        output = str(e)
    ITERATION += 1
    return output

DONE_POV_FILE = 'done_pov.txt'
DONE_GP_FILE = 'done_gp.txt'
NO_VUL_FILE = 'no_vulnerability_commits.txt'
done_pov_file_path = os.path.join(CRS_SCRATCH_SPACE, DONE_POV_FILE)
done_gp_file_path = os.path.join(CRS_SCRATCH_SPACE, DONE_GP_FILE)
no_vul_file_path = os.path.join(CRS_SCRATCH_SPACE, NO_VUL_FILE)

def run_test_litellm(commit_file):
    while True:
        done_povs = ''
        done_gps = ''
        no_vuls = ''
        if os.path.exists(done_pov_file_path):
            with open(done_pov_file_path, 'r') as file:
                done_povs = file.read()
        if os.path.exists(done_gp_file_path):
            with open(done_gp_file_path, 'r') as file:
                done_gps = file.read()
        if os.path.exists(no_vul_file_path):
            with open(no_vul_file_path, 'r') as file:
                no_vuls = file.read()

        if done_gps.count(commit_file) > 0:
            print(f"Skipping {commit_file} because it is successfully patched!")
            break
        # run at most five times for No vulnerability
        if no_vuls.count(commit_file) > 5:
            print(f"Skipping {commit_file} because it is likely not vulnerable")
            break

        if commit_file in done_povs:
            print(f"TODO: already done POV for {commit_file}, but need to do more with patch generation")
            break
        #now keep trying for a commit that's potentially vulnerable
        result = run_test_litellm_internal(commit_file)
        print(result)  

# Iterate over each CP directory and process it
for cp in cp_dirs:
    cp_path = os.path.join(CRS_SCRATCH_SPACE, CRS_HOSTNAME+"/"+cp)
    print(f"Processing CP: {cp_path}")
    
    # Change to the CP directory
    os.chdir(cp_path)
    
    print(f"Building the initial project from HEAD")
    build_initial_project()

    # Execute the extract_commits.py script
    success, stdout, stderr = execute_script('extract_commits.py')

    # Check the function return to ensure no error
    if success:
        print(stdout)
        commit_files = []
        with open('commits.txt', 'r') as file:
            commit_files = [line.strip() for line in file.readlines()]
        num_commits = len(commit_files)
        #num_cores = multiprocessing.cpu_count()
        num_cores= get_cpu_cores_via_cgroups()

        print(f'Number of commits: {num_commits}')
        print(f'Number of cores: {num_cores}')

        start_time = time.time()

        # Add your analysis code here
        while True:
            # Run the test_litellm.py script
            # command = ['python3', 'test_litellm.py']
            # try:
            #     result = subprocess.run(command, check=True, capture_output=True, text=True)
            #     output = result.stdout + result.stderr
            # except subprocess.CalledProcessError as e:
            #     output = e.stdout + e.stderr
            # except Exception as e:
            #     output = str(e)

            # print(output)
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {executor.submit(run_test_litellm, commit_file): commit_file for commit_file in commit_files}
                while futures:
                    done, not_done = concurrent.futures.wait(futures, timeout=60, return_when=concurrent.futures.FIRST_COMPLETED)
                    for future in done:
                        commit_file = futures.pop(future)
                        try:
                            result = future.result()
                            print(f'Output for {commit_file}:\n{result}\n')
                        except Exception as e:
                            print(f'Error processing {commit_file}: {e}')
                    # Small sleep to avoid busy waiting, adjust as necessary
                    time.sleep(0.1) 

            #TODO check scoring progress

            # Check if the total timeout has been reached
            if time.time() - start_time >= total_timeout:
                print("Total timeout reached.")
                # break
    else:
        print("An error occurred while extracting commits.")
        print(stderr)
    # Change back to the root folder to continue the iteration
    os.chdir(CRS_SCRATCH_SPACE)
