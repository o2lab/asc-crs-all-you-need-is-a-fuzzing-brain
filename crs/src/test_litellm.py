from litellm import completion
import os
import time
import base64
import io
import yaml
import subprocess
import sys
import json
import requests
import re
import tempfile
import shutil
import pwd
import grp
import argparse
import hashlib

def compute_hash_hex(vds_data) -> str:
    # Convert the dictionary to a JSON string
    vds_data_str = json.dumps(vds_data, sort_keys=True)
    # Create a hash object
    hash_obj = hashlib.sha256(vds_data_str.encode())
    # Get the hexadecimal digest of the hash
    hash_hex = hash_obj.hexdigest()
    return hash_hex

# if True:
#     sample_linux_content = '?UDP1,O@,"3D??"3D?\??"3DHAXX?CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
#     sample_blob_file_name = 'sample_linux.bin'
#     if os.path.exists(sample_blob_file_name):
#         with open(sample_blob_file_name, 'rb') as file:
#             sample_linux_content = file.read()
#     print(f"sample_linux_content:{sample_linux_content}")
#     exit(0)

# def remove_second_segment(path):
#     segments = path.split('/')
#     if len(segments) > 2:
#         segments.pop(2)
#     return '/'.join(segments)

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Process a commit file.')
parser.add_argument('commit_file', type=str, nargs='?', default='', help='The commit file to process')
args = parser.parse_args()

target_commit_file = args.commit_file
if len(target_commit_file) > 0:
    # Your existing logic to process the commit file
    print(f'Processing commit file: {target_commit_file}')

current_cp_directory_x = os.getcwd()
CP_ROOT = os.getenv('AIXCC_CP_ROOT')
LITELLM_HOSTNAME = os.getenv('AIXCC_LITELLM_HOSTNAME')
LITELLM_KEY = os.getenv('LITELLM_KEY')
LOCAL_TESTING = False
if LITELLM_HOSTNAME == None or LITELLM_KEY == None: 
    ## set ENV variables
    if os.getenv('OPENAI_API_KEY') == None: 
        print(f"for local testing only, please export OPENAI_API_KEY=your_key")
        exit(-1)
    else:
        LOCAL_TESTING = True

URL = f"{LITELLM_HOSTNAME}/chat/completions"
print(f"URL: {URL}")
HEADER = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {LITELLM_KEY}"
}
OPENAI_MODEL = "gpt-4o"
CLAUDE_MODEL = "claude-3-5-sonnet-20240620"
GOOGLE_MODEL = "gemini-1.5-pro-preview-0514"

def call_litellm(messages,model) -> str:
    if model == OPENAI_MODEL:
        model = "oai-gpt-4o"
    elif model == CLAUDE_MODEL:
        model = "claude-3.5-sonnet"
    else:
        model = "gemini-1.5-pro"

    data = {
            "model": model,
            "temperature": 1.0, 
            "messages":messages
    }
    # Make the POST request
    # print(f"call_litellm messages: {messages}")
    response = requests.post(URL, headers=HEADER, json=data)
    result = response.json()
    # print(f"call_litellm response:{result}")
    if response.status_code == 200:
        return result['choices'][0]['message']['content']
    return f"Error from litellm: {result}"

# check LiteLLM
# if LOCAL_TESTING == False:
#     messages = [{ "content": 'what is your model version?',"role": "user"}]
#     if call_litellm(messages) == 'error':
#         # LOCAL_TESTING = True
#         print(f"ERROR call_litellm on CRS Competition or Github server!")

def call_llm_x(messages,model) -> str:
    if LOCAL_TESTING == True:
        print(f"call_llm LOCAL_TESTING: {LOCAL_TESTING}")
        response = completion(model=model, temperature=1.0, messages=messages)
        return response.choices[0].message.content
    else:
        return call_litellm(messages,model)

def call_llm(messages) -> str:
    try:
       result = call_llm_x(messages,OPENAI_MODEL)
    except Exception as e:
        print(f"litellm completion failed for {OPENAI_MODEL}: {e}")
        try:
            result = call_llm_x(messages,CLAUDE_MODEL)
        except Exception as e:
            print(f"litellm completion failed for {CLAUDE_MODEL}: {e}")
            result = call_llm_x(messages,GOOGLE_MODEL)

    return result

def call_llm_for_patch(messages) -> str:
    try:
       result = call_llm_x(messages,CLAUDE_MODEL)
    except Exception as e:
        print(f"litellm completion failed for {CLAUDE_MODEL}: {e}")
        try:
            result = call_llm_x(messages,OPENAI_MODEL)
        except Exception as e:
            print(f"litellm completion failed for {OPENAI_MODEL}: {e}")
            result = call_llm_x(messages,GOOGLE_MODEL)

    return result

CRS_SCRATCH_SPACE = os.getenv('AIXCC_CRS_SCRATCH_SPACE')
if CRS_SCRATCH_SPACE is None:
    #for localhost testing
    CRS_SCRATCH_SPACE = '../'
DONE_POV_FILE = 'done_pov.txt'
DONE_GP_FILE = 'done_gp.txt'
NO_VUL_FILE = 'no_vulnerability_commits.txt'
done_pov_file_path = os.path.join(CRS_SCRATCH_SPACE, DONE_POV_FILE)
done_gp_file_path = os.path.join(CRS_SCRATCH_SPACE, DONE_GP_FILE)
no_vul_file_path = os.path.join(CRS_SCRATCH_SPACE, NO_VUL_FILE)

CAPI_HOSTNAME = os.getenv('AIXCC_API_HOSTNAME')
if CAPI_HOSTNAME == None:
    #for localhost testing
    CAPI_HOSTNAME="http://localhost:8080"

AUTH = ('00000000-0000-0000-0000-000000000000', 'secret')

TRY_POV_TIMES = 3
TRY_PATCH_TIMES = 5

# Function to make cAPI request
def make_request(method, endpoint, data=None):
    url = f"{CAPI_HOSTNAME}/{endpoint}"
    response = requests.request(method, url, auth=AUTH, json=data)
    return response.json()

def extract_diff_info(diff_content):
    lines = diff_content.split('\n')
    diff_info = []
    current_file = None
    current_hunk = None
    current_hunk_lines = []
    start_line_number = 0
    end_line_number = 0
    
    for line in lines:
        if line.startswith('--- '):
            if current_file is not None:
                # Save previous file's hunk if any
                if current_hunk is not None:
                    current_file['hunks'].append({
                        "hunk_lines": current_hunk_lines,
                        "start_line_number": start_line_number,
                        "end_line_number": end_line_number
                    })
                diff_info.append(current_file)
            current_file = {"file": line[5:].strip(), "hunks": []}
            current_hunk = None
            current_hunk_lines = []
        elif line.startswith('+++ '):
            full_file_path = line[5:].strip()
            if not full_file_path.endswith("dev/null"):
                current_file["file"] = full_file_path
        elif line.startswith('@@'):
            if current_hunk is not None:
                current_file['hunks'].append({
                    "hunk_lines": current_hunk_lines,
                    "start_line_number": start_line_number,
                    "end_line_number": end_line_number
                })
            current_hunk = line
            current_hunk_lines = []
            match = re.search(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@', line)
            if match:
                start_line_minus = int(match.group(1))
                length_minus = int(match.group(2))
                start_line_plus = int(match.group(3))
                length_plus = int(match.group(4))
                
                start_line_number = min(start_line_plus,start_line_minus)
                end_line_number = max(start_line_minus + length_minus, start_line_plus + length_plus)
                
        elif current_hunk is not None:
            current_hunk_lines.append(line)
    
    if current_file is not None and current_hunk is not None:
        current_file['hunks'].append({
            "hunk_lines": current_hunk_lines,
            "start_line_number": start_line_number,
            "end_line_number": end_line_number
        })
        diff_info.append(current_file)
    
    return diff_info

# diff_content="""diff --git b/net/tipc/crypto.c a/net/tipc/crypto.c
# index 43fc66bd1..2521298f2 100644
# --- b/net/tipc/crypto.c
# +++ a/net/tipc/crypto.c
# @@ -2307,9 +2307,9 @@ static bool tipc_crypto_key_rcv(struct tipc_crypto *rx, struct tipc_msg *hdr)
 
#  	/* Copy key from msg data */
#  	skey->keylen = keylen;
# -	memcpy(skey->alg_name, data, TIPC_AEAD_ALG_NAME);
# -	memcpy(skey->key, data + TIPC_AEAD_ALG_NAME + sizeof(__be32),
# -	       skey->keylen);
# +	//memcpy(skey->alg_name, data, TIPC_AEAD_ALG_NAME);
# +	//memcpy(skey->key, data + TIPC_AEAD_ALG_NAME + sizeof(__be32),
# +	//       skey->keylen);
 
#  	rx->key_gen = key_gen;
#  	rx->skey_mode = msg_key_mode(hdr);
# }
# """
# if True:
#     diff_info = extract_diff_info(diff_content)
#     print(diff_info)
#     exit(0)

# Load the project.yaml file
with open('project.yaml', 'r') as file:
    project_yaml = yaml.safe_load(file)

# Get the cp_name from the loaded YAML
cp_name = project_yaml.get('cp_name')

# Get the cp_name from the loaded YAML
language = project_yaml.get('language')

harnesses = project_yaml.get('harnesses', {})

for harness_id, harness_info in harnesses.items():
    name = harness_info.get('name')
    source = harness_info.get('source')
    print(f"ID: {harness_id}, Name: {name}, Source: {source}")

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

def extract_python_code(text: str) -> str:
    prompt_extract_code_pre ="""Can you extract Python code from the following text to generate test input? Just return the code, no explanation. So I can directly exec it to get the input data.
========================

"""
    full_prompt_extract_code = prompt_extract_code_pre+text
    messages = [{ "content": full_prompt_extract_code,"role": "user"}]
    return call_llm(messages)

def extract_python_code_for_patch(text: str) -> str:
    prompt_extract_code_pre ="""Can you extract Python code from the following text to generate patch? Just return the code, no explanation. So I can directly exec it to generate the patch.
========================

"""
    full_prompt_extract_code = prompt_extract_code_pre+text
    messages = [{ "content": full_prompt_extract_code,"role": "user"}]
    return call_llm(messages)

def extract_diff_for_patch(patch_gpt4_result):
    # Extract the actual diff content from the provided result.
    # This implementation assumes the diff is enclosed in triple backticks.
    start_marker = "```diff"
    end_marker = "```"
    
    start_index = patch_gpt4_result.find(start_marker)
    end_index = patch_gpt4_result.find(end_marker, start_index + len(start_marker))
    
    if start_index == -1 or end_index == -1:
        print("Diff marker ```diff not found in the provided result.")
        start_marker = "```"
        end_marker = "```"
        start_index = patch_gpt4_result.find(start_marker)
        end_index = patch_gpt4_result.find(end_marker, start_index + len(start_marker))

    # Extract the diff content between the markers
    return patch_gpt4_result[start_index + len(start_marker):end_index].strip()


def run_pov(harness_name:str,pov_file:str) -> str:
    sanitizer_triggered = ""
    # Check if pov_x.bin exists
    if os.path.isfile(pov_file):
        # Define the command to run
        command = ['./run.sh', '-x', 'run_pov', pov_file, harness_name]

        # Execute the command
        try:
            result = subprocess.run(command, timeout=150, check=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            output = e.stdout + e.stderr
        except Exception as e:
            output = str(e)

        # Check if any sanitizer is triggered
        for sanitizer_id, sanitizer_string in project_yaml.get('sanitizers', {}).items():
            if sanitizer_string in output:
                sanitizer_triggered = sanitizer_id
                break

        # Print the result
        if sanitizer_triggered:
            print(f"Sanitizer triggered: {sanitizer_triggered} by {pov_file}")
        else:
            print(f"No sanitizer triggered by {pov_file}")
    return sanitizer_triggered

def validate_pov(sanitizer_id0:str, commit_id:str, harness_name:str, pov_file:str)-> str:
    global CP_ROOT
    if CP_ROOT == None:
        #local testing, just return
        return sanitizer_id0

    sanitizer_triggered = ""
    short_commit_id = commit_id[:4]
    global current_cp_directory_x
    # TODO: create a new directory "pov_'commit_id'" for the cp
    base_dir, cp = os.path.split(current_cp_directory_x)
    pov_directory = f"{base_dir}/pov_{short_commit_id}/"
    pov_cp_path = os.path.join(pov_directory, cp)
    print(f"Copy cp to scratch pov {pov_cp_path}")
    src = os.path.join(CP_ROOT, cp)
    dest = pov_directory
    subprocess.run(['rsync', '--archive', '--delete', src, dest])
    # copy blob_file and enter the new directory, 
    shutil.copy(pov_file, pov_cp_path)
    # Go to the new directory, 
    os.chdir(pov_cp_path)
    user, group = get_current_user_and_group()
    pov_cp_path_src = pov_cp_path+'/src/'
    cp_sources = project_yaml.get('cp_sources', {})
    for source_name, details in cp_sources.items():
        repo_path_source = os.path.join(pov_cp_path_src, source_name)
        change_ownership_and_permissions(repo_path_source,user,group)
        subprocess.run(["git", "config", "--add", "safe.directory", repo_path_source])

    for source_name, details in cp_sources.items():
        #reset to commit_id and build 
        command = ['git', '-C', 'src/'+source_name, 'reset', '--hard', commit_id]
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            if result.returncode != 0:
                #wrong source_name
                continue
        except Exception as e:
            continue
        
        print(f"validate_pov: make sure {sanitizer_id0} is triggered at {commit_id}")
        command = ['./run.sh', '-x', 'build']
        subprocess.run(command, check=True, capture_output=True, text=True)
        #now test the pov, make sure it is triggered
        command = ['./run.sh', '-x', 'run_pov', pov_file, harness_name]
        try:
            result = subprocess.run(command, timeout=150, check=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            output = e.stdout + e.stderr
        except Exception as e:
            output = str(e)
        # Check if any sanitizer is triggered
        for sanitizer_id, sanitizer_string in project_yaml.get('sanitizers', {}).items():
            if sanitizer_string in output:
                if sanitizer_id == sanitizer_id0:
                    print(f"validate_pov: okay {sanitizer_id} is triggered at {commit_id}")
                    sanitizer_triggered = sanitizer_id
                break
        
        if len(sanitizer_triggered)>0:
            print(f"validate_pov: make sure {sanitizer_triggered} is not triggered before {commit_id}")
            #now check the state before commit
            command = ['git', '-C', 'src/'+source_name, 'reset', '--hard', commit_id+'^']
            subprocess.run(command, check=True, capture_output=True, text=True)
            command = ['./run.sh', '-x', 'build']
            subprocess.run(command, check=True, capture_output=True, text=True)
            command = ['./run.sh', '-x', 'run_pov', pov_file, harness_name]
            try:
                result = subprocess.run(command, timeout=150, check=True, capture_output=True, text=True)
                output = result.stdout + result.stderr
            except subprocess.CalledProcessError as e:
                output = e.stdout + e.stderr
            except Exception as e:
                output = str(e)
            # Check if any sanitizer is triggered
            for sanitizer_id, sanitizer_string in project_yaml.get('sanitizers', {}).items():
                if sanitizer_string in output:
                    print(f"validate_pov: {sanitizer_id} is still triggered before {commit_id}")
                    if sanitizer_triggered == sanitizer_id:
                        #if still triggered, then not valid
                        sanitizer_triggered = ""
                        break
        break

    os.chdir(current_cp_directory_x)
    return sanitizer_triggered

# sanitizer_id='id_2'
# commit_id='22e7f707e16ab7f6ef8a7e9adbb60b24bde49e27'
# harness_name='filein_harness'
# blob_file='sample_mock2.bin'

# sanitizer_id='id_1'
# commit_id='22e7f707e16ab7f6ef8a7e9adbb60b24bde49e27'
# harness_name='filein_harness'
# blob_file='sample_mock1.bin'
# sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)
# print(f"testing sanitizer_id: {sanitizer_id}") 

def submit_vds(cp_name:str,commit_id:str,sanitizer_id:str,harness_id:str,blob_file:str) -> dict:
    # Submit VDS
    print("Now that we've confirmed that our VDS works, let's submit it.")
    print("Using the contents of the CP's project.yaml, we can convert our harness & sanitizer to the CP's canonical names.\n")

    # harness_id = next(key for key, value in project_yaml['harnesses'].items() if value['name'] == llm_response_harness)
    # sanitizer_id = next(key for key, value in project_yaml['sanitizers'].items() if value == llm_response_sanitizer)

    # Read the content of the file
    with open(blob_file, 'rb') as file:
        llm_response_blob = file.read()
    print(f"{blob_file} data:\n{llm_response_blob}")
    # Encode the content in base64
    b64_blob = base64.b64encode(llm_response_blob).decode('utf-8')

    # Print the base64-encoded string
    # print(b64_blob)

    vds_data = {
        "cp_name": cp_name,
        "pou": {
            "commit_sha1": commit_id,
            "sanitizer": sanitizer_id
        },
        "pov": {
            "harness": harness_id,
            "data": b64_blob
        }
    }
    print(f"vds_data:\n{vds_data}")
    rejected_pov_file_path = f"rejected_povs_{commit_id}_{sanitizer_id}.txt"
    hash_hex = compute_hash_hex(vds_data)
    if os.path.exists(rejected_pov_file_path):
        with open(rejected_pov_file_path, 'r') as file:
            rejected_povs = file.read()
            # if hash_hex already rejected, then return 
            if True or rejected_povs.count(hash_hex) > 0:
                vds_status = {
                    "status": "rejected"
                }
                return vds_status

    print("\nNow that we have the inputs we need for the API, we can go ahead and submit our VDS.\n")
    vds_response = make_request('POST', 'submission/vds/', vds_data)
    print(json.dumps(vds_response, indent=2))

    vds_uuid = vds_response['vd_uuid']
    print("\nThe cAPI is now evaluating our Vulnerability Discovery Submission (VDS). Its status will be pending until the cAPI runs all the tests.\n")

    while True:
        #avoid race condition
        global done_pov_file_path
        if os.path.exists(done_pov_file_path):
            with open(done_pov_file_path, 'r') as file:
                done_povs = file.read()
                if commit_id in done_povs:
                    vds_status = {
                            "status": "duplicated"
                    }
                    return vds_status

        vds_status = make_request('GET', f'submission/vds/{vds_uuid}')
        print(json.dumps(vds_status, indent=2))
        if vds_status['status'] != 'pending':
            break
        time.sleep(10)
        print("\nWaiting for VDS to finish testing...\n")

    print("\nAt this point, the VDS has been fully tested. It could either be accepted or rejected.")
    if vds_status['status'] == 'rejected':
        print(f"Bad luck VDS was rejected for {commit_id}, let's save to file so won't submit duplidates to avoid penalty.")
        with open(rejected_pov_file_path, 'a') as file:
            file.write(hash_hex+'\n')
        # it could be that the commit itself is not vulnerable, so we save it too
        global no_vul_file_path
        with open(no_vul_file_path, 'a') as file:
            for _ in range(1):
                file.write(commit_id+'.txt\n')
    return vds_status

def reset_head_and_build() -> bool:
    # First, clean state from HEAD
    # git -C src/linux_kernel reset --hard HEAD
    
    cp_sources = project_yaml.get('cp_sources', {})
    for source_name, details in cp_sources.items():
        # Define the command to run
        command = ['git', '-C', 'src/'+source_name, 'reset', '--hard', 'HEAD']
        # Execute the command
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            output = e.stdout + e.stderr
        except Exception as e:
            output = str(e)

        command = ['./run.sh', '-x', 'build']
        # this may take a while
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            output = e.stdout + e.stderr
        except Exception as e:
            output = str(e)
    return True

# % tree
# % awk 'NR>=1 && NR<=100 {printf "%-3s%d %s\n", "", NR, $0}' src/service.c
# % wc -l src/service | awk '{print $1}'
# % git apply -p0 diff.patch
ALLOW_COMMANDS=["tree","awk","wc","git","echo","cp","python","make","sed","perl"]
def execute_shell(command: str) -> str:
    # print(f"execute_shell command: {command}")
    command_name = command.split()[0]
    if command_name not in ALLOW_COMMANDS:
        return ""
    result = subprocess.run(command, capture_output=True, shell=True)
    if len(result.stderr.decode())>0:
        return f"STDERR:{result.stderr.decode()}"

    return result.stdout.decode()

# Function to count modified files and hunks
def count_files_and_hunks(diff_content):
    lines = diff_content.split('\n')
    modified_files = set()
    hunk_count = 0
    
    for line in lines:
        if line.startswith('+++') or line.startswith('---'):
            modified_files.add(line[4:].strip())
        elif line.startswith('@@'):
            hunk_count += 1
            
    return len(modified_files), hunk_count

def find_cp_source_name (file: str) -> str:
    cp_sources = project_yaml.get('cp_sources', {})
    for source_name, details in cp_sources.items():
        file_path = 'src/'+source_name+'/'+file
        if os.path.isfile(file_path):
            return source_name
    print(f"Failed to find cp source_name for {file}")
    return ''

#TODO handle changes in multiple files
def correct_patch_content(patch_diff: str, file, source_name,diff_info, error_msg: str) -> str:
    source_lines = get_relevant_source_lines(file, source_name,diff_info)
    prompt_correct_patch =f"""The following diff patch fails with {error_msg}========================
{patch_diff}========================
Can you fix the patch? Make sure the source code lines from the original file are matched exactly. Pay specical attention to the number of spaces. 

Here are the relevant source code of {file}:
{source_lines}
"""
    print(prompt_correct_patch)
    messages = [{ "content": prompt_correct_patch,"role": "user"}]
    patch_gpt4_result = call_llm_for_patch(messages)
    print(patch_gpt4_result)
    patch_diff = extract_diff_for_patch(patch_gpt4_result)+"\n"
    return patch_diff

#TODO: handle patches that span multiple cp sources
def apply_patch(patch_file:str) -> (bool,str):
    
    success = False
    output = ''

    cp_sources = project_yaml.get('cp_sources', {})
    for source_name, details in cp_sources.items():
        
        # ./run.sh -x build patch_file linux_kernel
        command = ['./run.sh', '-x', 'build', patch_file, source_name]
        print(f"apply_patch command: {command}")
        # this may take a while
        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
        except subprocess.CalledProcessError as e:
            output = e.stdout + e.stderr
        except Exception as e:
            output = str(e)
        #TODO: check patching message
        if 'Patching failed' in output or 'corrupt patch' in output:
            # failed patch
            print(f"{output}")
        else:
            print(f"Patch {patch_file} applied successfully")
            success = True
            break

    return success, output

def validate_patch(harness_name:str,blob_file:str) -> (bool,str):
    print(f"Validating Patch: this may take a while ...")
    sanitizer_id = run_pov(harness_name,blob_file)
    # is the following true?
    # if valid patch, should not trigger any sanitizer message
    if len(sanitizer_id) == 0: 
        #./run.sh -x run_tests
        command = ['./run.sh', '-x', 'run_tests']
        # this may take a while
        try:
            result = subprocess.run(command, timeout=150, check=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
            if result.returncode == 0 or 'exit=0' in output or 'Result: PASS' in output or 'tests all passed' in output:
                return True, output
        except subprocess.CalledProcessError as e:
            output = e.stdout + e.stderr
        except Exception as e:
            output = str(e)

        return False, output

    return False, f"The patch is invalid because {sanitizer_id} is still triggered"

commit_gpt4_result0="""
Yes, this commit does introduce a potential vulnerability in the Nginx code.

Specifically, the change made in `ngx_http_userid_filter_module.c`:

```diff
-    src.len = 22;
+   dst.data = (u_char *) ctx->uid_got;
```

Previously, the length of the `src` was limited to 22 characters. This was likely a measure to prevent buffer overflow or other unexpected behavior due to excessively long input. By removing this restriction, the code no longer limits the length of the input, which could result in processing of longer-than-expected strings.

Buffer overflow vulnerabilities occur when there is no boundary check on the length of input being processed, potentially allowing an attacker to overwrite adjacent memory and control the execution flow of the program. This can lead to arbitrary code execution, crashes, or other unintended behavior.

In summary, this change removes an important boundary check (`src.len = 22;`), which can introduce a buffer overflow vulnerability in the code, potentially allowing attackers to exploit this and cause severe security issues.
"""

harness_gpt4_result0="""Sure, I'll help generate an input that could exploit the potential buffer overflow vulnerability in the `ngx_http_userid_filter_module.c` using the given test harness. Since the vulnerability is related to the base64 decoding of user_id, we need to craft a request that likely overflows the buffer allocated for the user_id processing.

    Here is some example input data:

    ```python
    import base64

    # Generate input longer than the expected 22 chars after base64 decoding
    input_data = "A" * 44  # As base64 encoding usually expands data by a factor of ~1.33, 44 chars should suffice
    encoded_data = base64.b64encode(input_data.encode()).decode()

    # Construct an example HTTP request incorporating the encoded data as a cookie
    http_request = f"GET / HTTP/1.1\r\nHost: localhost\r\nCookie: uid={encoded_data}\r\n\r\n"

    # Print out the crafted HTTP request
    print(http_request)
    ```

You can feed this generated input directly to the test harness. The rationale behind this input is that by having a very long base64 string encoded which, when decoded, exceeds the previously hardcoded limit of 22 characters, it could cause the buffer overflow condition that was being protected against prior to the commit changes.

For inclusion in the test harness in a C-generated format:

```c
const uint8_t fuzzer_input[] = 
    "GET / HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Cookie: uid=QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ=="
    "\r\n\r\n";
size_t fuzzer_input_size = sizeof(fuzzer_input) - 1;
LLVMFuzzerTestOneInput(fuzzer_input, fuzzer_input_size);
```

In this case, `QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==` represents a base64 encoded string that is 44 characters long, which will decode to a string of 33 bytes, thus exceeding the previously enforced 22-byte limit.

When you run this with your test harness, it should expose the vulnerability, leading to possible overflow conditions.
"""

def remove_lines_before_diff(text):
    lines = text.split('\n')
    start_index = 0
    
    for i, line in enumerate(lines):
        if line.startswith('diff --git') and (line.endswith(".c") or line.endswith(".h") or line.endswith(".java")):
            start_index = i
            break
            
    return '\n'.join(lines[start_index:])

def get_relevant_source_lines(file,source_name,diff_info) -> str:
    
    file_path = 'src/'+source_name+'/'+file
    command_get_largest_line_number = "awk 'END {print NR}' "+str(file_path)
    file_largest_line = execute_shell(command_get_largest_line_number)
    file_largest_line = int(file_largest_line.strip())

    #show at most 100 lines of code
    MAX_LINES = 100
    if file_largest_line <= MAX_LINES:
        command_get_source_lines = "awk 'NR>="+str(0)+" && NR<="+str(file_largest_line)+" {printf \"%s%d %s\\n\", \"\", NR, $0}' " +file_path
        print(f"% {command_get_source_lines}")
        source_lines = execute_shell(command_get_source_lines)
        return source_lines
    
    source_lines = ""
    last_end_line = 0

    for hunk in diff_info['hunks']:
        start_line = hunk["start_line_number"]
        end_line = hunk["end_line_number"]
        
        delta = end_line - start_line
        if delta < MAX_LINES:
            delta_x = (MAX_LINES - delta)/2
            start_line = start_line - delta_x
            if start_line<0:
                start_line =0
            end_line = end_line + delta_x

        if last_end_line > 0:
            if start_line <= last_end_line:
                start_line = last_end_line+1
                end_line = start_line +MAX_LINES

        # TODO the source code may have been changed by later commits, such as refactor, so we need to show the latest code
        command_get_source_lines = "awk 'NR>="+str(start_line)+" && NR<="+str(end_line)+" {printf \"%s%d %s\\n\", \"\", NR, $0}' " +file_path
        print(f"% {command_get_source_lines}")
        source_lines_hunk = execute_shell(command_get_source_lines)
        source_lines +=source_lines_hunk
        last_start_line = start_line
        last_end_line = end_line

    return source_lines

# commit_file="11dafa9a5babc127357d710ee090eb4c0c05154f.txt"
# if len(target_commit_file)>0:
#     commit_file = target_commit_file
# with open(commit_file, "r") as file:
#     prompt_commit_data = file.read()
#     print(f"Analyzing {prompt_commit_data}")

# diff_content = remove_lines_before_diff(prompt_commit_data)
# diff_infos = extract_diff_info(diff_content)
# print(f"diff_info number_of_files: {len(diff_infos)}")
# for file_info in diff_infos:
#     print(f"Modified File: {file_info['file']}")
#     for hunk in file_info['hunks']:
#         print(f"  Hunk (lines {hunk['start_line_number']} to {hunk['end_line_number']}):")
#         for line in hunk['hunk_lines']:
#             print(f"    {line}")

# # TODO handle multiple files
# diff_info = diff_infos[0]
# file = diff_info["file"]
# source_name = find_cp_source_name(file)
# # get source code snippets
# source_lines = get_relevant_source_lines(file,source_name,diff_info)
# prompt_source_lines = f"""Here are the relevant source code of {file}:
# {source_lines}
# """
# print(f"prompt_source_lines:\n{prompt_source_lines}")
# exit(0)

def check_commit(cp_name:str, commit_file:str,messages) -> str:
    prompt_commit_pre = f"""Here is a commit introduced into {cp_name}. Does it introduce any vulnerability? If yes, explain the vulnerability and return **Result: YES**. Otherwise, return **Result: No**.
The following CWEs are in scope:
• C
o CWE-125
o CWE-787 + CWE119 
o CWE-416 + CWE-415
o CWE-476
o CWE-190
• Java
o CWE-22
o CWE-77
o CWE-78
o CWE-94
o CWE-190
o CWE-434
o CWE-502
o CWE-918
Note that only the code changes, i.e., additions and deletions in this commit are of interest. If the code in the context contains a vulnerability but the code changes do not introduce a vulnerability, then return **Result: YES context only**.
If the commit only refactors the code, e.g., renaming variables, then return **Result: No**. 

"""
    # Read from a file containing the commit data
    with open(commit_file, "r") as file:
        prompt_commit_data = file.read()
        print(f"Analyzing {prompt_commit_data}")

    diff_content = remove_lines_before_diff(prompt_commit_data)
    diff_infos = extract_diff_info(diff_content)
    print(f"diff_info number_of_files: {len(diff_infos)}")
    for file_info in diff_infos:
        print(f"Modified File: {file_info['file']}")
        for hunk in file_info['hunks']:
            print(f"  Hunk (lines {hunk['start_line_number']} to {hunk['end_line_number']}):")
            for line in hunk['hunk_lines']:
                print(f"    {line}")

    # TODO handle multiple files
    if len(diff_infos) > 0:
        diff_info = diff_infos[0]
        file = diff_info["file"]
        source_name = find_cp_source_name(file)
        # get source code snippets
        source_lines = get_relevant_source_lines(file,source_name,diff_info)
        prompt_source_lines = f"""\Here are the relevant source code of {file}:
{source_lines}
"""
    else:
        prompt_source_lines=""

    # Concatenate the initial prompt with the commit data from the file
    full_prompt_commit = prompt_commit_pre + prompt_commit_data+prompt_source_lines

    messages.append({"content": full_prompt_commit, "role": "user"})

    commit_gpt4_result = call_llm(messages)
    print(commit_gpt4_result)
    return commit_gpt4_result

# harness_source = "src/harnesses/pov_harness.cc"
def generate_povs_for_harness(harness_id:str,harness_name:str,harness_source:str,blob_file:str,messages) -> str:
    #gpt4o generate Python code 
    prompt_harness_pre=f"""Thanks! You are an expert in software security testing. I have a test harness below.
    Can you generate an input that could exploit the potential vulnerability using the given test harness?
    Note that the input will be passed to the test harness, so make sure to include proper data format, e.g., http Header.
    In the input, generate longer payload than expected because the code may contain internal filters. But limit the payload size to at most a few thousand bytes. 
    Please return Python code to generate the input and save it in a file '{blob_file}'.
For Java projects such as Jenkins, Jazzer sanitizers are used to detect if a vulnerability is triggered or not. Here are some environment variables for the built-in sanitizers: 
    | ENV_VARIABLE                             | Default              | Sanitizer                  | Notes                                                                                                                                                                                                                                |
|------------------------------------------|----------------------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `JAZZER_SSRF`                            | `jazzer.example.com` | `ServerSideRequestForgery` | Checks for host name equals                                                                                                                                                                                                          |
| `JAZZER_FILE_SYSTEM_TRAVERSAL_FILE_NAME` | `jazzer-traversal`   | `FileSystemTraversal`      | Checks for a file or path ending with this sentinel when reading or writing a file AND <br/> checks that the file is within the allowed (comma-delimited) directories specified by <br/>the system property `jazzer.fs_allowed_dirs` |
| `JAZZER_FILE_READ_WRITE`                 | `jazzer`             | `FileReadWrite`            | Checks for a file or path ending with this sentinel when reading or writing a file                                                                                                                                                   |
| `JAZZER_COMMAND_INJECTION`               | `jazze`              | `OSCommandInjection`       | Checks for a command or argument that equals this string      

For instance, OSCommandInjection may use 'jazze' as the command, so you may use 'jazze' in some of your inputs. For example, count = 1, picker = 13, and fuzzinput = "x-evil-backdoor\0breakin the law\0jazze".
The POV file contains ^@^@^@^M^@^@^@^Ax-evil-backdoor^@breakin the law^@jazze
    """
    with open(harness_source, "r") as file:
        prompt_harness_data = file.read()

    full_prompt_harness = prompt_harness_pre + prompt_harness_data
    messages.append({"content": full_prompt_harness, "role": "user"})
    harness_gpt4_result = call_llm(messages)
    print(harness_gpt4_result)  
    try:         
        python_code = extract_python_code(harness_gpt4_result)
        python_code_cleaned = python_code.strip('```python').strip('```')
        exec_clean_python_code(python_code_cleaned)
    except Exception as e:
            print(f"An unexpected error occurred in generate_povs_for_harness: {e}")
    return harness_gpt4_result

def exec_clean_python_code(python_code_cleaned:str):
    print(f"python_code_cleaned:\n{python_code_cleaned}")

    # Create a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as temp_file:
        temp_file_name = temp_file.name
        temp_file.write(python_code_cleaned.encode('utf-8'))

    try:
        # Execute the temporary file with a timeout of 3 seconds
        result = subprocess.run(['python3', temp_file_name], timeout=3, capture_output=True, text=True)
        
        # Print stdout if not empty
        if result.stdout:
            print(f"stdout:\n{result.stdout}")

        # Print stderr if not empty
        if result.stderr:
            print(f"stderr:\n{result.stderr}")
        
    except subprocess.TimeoutExpired:
        print("The script timed out.")

    finally:
        # Clean up the temporary file
        os.remove(temp_file_name)
    
def generate_povs_for_harness_java(harness_id:str,harness_name:str,harness_source:str,blob_file:str,messages) -> (str, str):
    #gpt4o generate Python code for java like Jenkins
    blob_file_prefix = blob_file.split('.bin')[0]
    sample_jenkins_content = '^@^@^@^M^@^@^@^Ax-evil-backdoor^@breakin the law^@jazze'
    sample_blob_file_name = 'sample_jenkins.bin'
    if os.path.exists(sample_blob_file_name):
        with open(sample_blob_file_name, 'rb') as file:
            sample_jenkins_content = file.read()

    prompt_harness_pre=f"""Thanks! You are an expert in software security testing. I have a test harness below.
Can you generate an input that could exploit the potential vulnerability using the given test harness?
Note that the input will be passed to the test harness, so make sure to include proper data format, e.g., http Header.
Please return Python code to generate five different and diverse inputs and save the ith input in file '{blob_file_prefix}_i.bin' (i from 1 to 5).
For Java projects such as Jenkins, Jazzer sanitizers are used to detect if a vulnerability is triggered or not. Here are some environment variables for the built-in sanitizers: 
    | ENV_VARIABLE                             | Default              | Sanitizer                  | Notes                                                                                                                                                                                                                                |
|------------------------------------------|----------------------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `JAZZER_SSRF`                            | `jazzer.example.com` | `ServerSideRequestForgery` | Checks for host name equals                                                                                                                                                                                                          |
| `JAZZER_FILE_SYSTEM_TRAVERSAL_FILE_NAME` | `jazzer-traversal`   | `FileSystemTraversal`      | Checks for a file or path ending with this sentinel when reading or writing a file AND <br/> checks that the file is within the allowed (comma-delimited) directories specified by <br/>the system property `jazzer.fs_allowed_dirs` |
| `JAZZER_FILE_READ_WRITE`                 | `jazzer`             | `FileReadWrite`            | Checks for a file or path ending with this sentinel when reading or writing a file                                                                                                                                                   |
| `JAZZER_COMMAND_INJECTION`               | `jazze`              | `OSCommandInjection`       | Checks for a command or argument that equals this string      

For instance, OSCommandInjection may use 'jazze' as the command, so you may use 'jazze' in some of your inputs. For example, count = 1, picker = 13, and fuzzinput = "x-evil-backdoor\0breakin the law\0jazze".
The sample POV file for nginx contains {sample_jenkins_content}
    """
    with open(harness_source, "r") as file:
        prompt_harness_data = file.read()

    full_prompt_harness = prompt_harness_pre + prompt_harness_data
    messages.append({"content": full_prompt_harness, "role": "user"})
    harness_gpt4_result = call_llm(messages)
    print(harness_gpt4_result)  
    try:         
        python_code = extract_python_code(harness_gpt4_result)
        python_code_cleaned = python_code.strip('```python\n').strip('```\n')
        exec_clean_python_code(python_code_cleaned)
    except Exception as e:
        print(f"TODO: an unexpected error occurred in generate_povs_for_harness_java: {e}")
        # return '', ''

    # the above should have created 'pov_i.bin'
    for i in range(5):
        x = i+1
        blob_file_i = f"{blob_file_prefix}_{x}.bin"
        print(f"checking POV {blob_file_i}")
        sanitizer_id = run_pov(harness_name,blob_file_i)
        if len(sanitizer_id)>0:
            shutil.copy(blob_file_i, blob_file)
            sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)

        if len(sanitizer_id)>0:
            print(f"successful POV generate_povs_for_harness_java: {blob_file_i}")
            #copy blob_file_i to blob_file
            return sanitizer_id, harness_gpt4_result    

    # TODO try fuzz w/ the sample pov
    if os.path.exists(sample_blob_file_name): 
        # TODO use llm to generate 10 variants of sample_pov
        messages.append({"content": harness_gpt4_result, "role": "assistant"})
        blob_file_prefix_sample = f"{blob_file_prefix}_sample"
        final_prompt_harness = f"Unfortunately, all POVs generated by your script failed. Can you give it a final try? Return Python code to generate ten different and diverse variants of the sample POV and save the ith input in file '{blob_file_prefix_sample}_i.bin' (i from 1 to 10)."
        messages.append({"content": final_prompt_harness, "role": "user"})
        harness_gpt4_result = call_llm(messages)
        print(harness_gpt4_result)  
        try:         
            python_code = extract_python_code(harness_gpt4_result)
            python_code_cleaned = python_code.strip('```python\n').strip('```\n')
            exec_clean_python_code(python_code_cleaned)
        except Exception as e:
            print(f"TODO final: an unexpected error occurred in generate_povs_for_harness_java: {e}")

        for i in range(10):
            x = i+1
            blob_file_i = f"{blob_file_prefix_sample}_{x}.bin"
            print(f"checking final POV {blob_file_i}")
            sanitizer_id = run_pov(harness_name,blob_file_i)
            if len(sanitizer_id)>0:
                shutil.copy(blob_file_i, blob_file)
                sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)

            if len(sanitizer_id)>0:
                print(f"final successful POV generate_povs_for_harness_java: {blob_file_i}")
                #copy blob_file_i to blob_file
                return sanitizer_id, harness_gpt4_result
        
        #final: use sample.bin itself
        sanitizer_id = run_pov(harness_name,sample_blob_file_name)
        if len(sanitizer_id)>0:
            shutil.copy(sample_blob_file_name, blob_file)
            sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)

        if len(sanitizer_id)>0:
            print(f"successful POV generate_povs_for_harness_java w/ sample: {sample_blob_file_name}")
            #copy blob_file_i to blob_file
            return sanitizer_id, harness_gpt4_result

    return '', ''

def generate_povs_for_harness_c_linux(harness_id:str,harness_name:str,harness_source:str,blob_file:str,messages) -> (str, str):
    #gpt4o generate Python code for java like Jenkins
    blob_file_prefix = blob_file.split('.bin')[0]
    
    sample_linux_content = '?UDP1,O@,"3D??"3D?\??"3DHAXX?CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    sample_blob_file_name = 'sample_linux.bin'
    if os.path.exists(sample_blob_file_name):
        with open(sample_blob_file_name, 'rb') as file:
            sample_linux_content = file.read()

    prompt_harness_pre=f"""Thanks! You are an expert in software security testing. I have a test harness below.
    Can you generate an input that could exploit the potential vulnerability using the given test harness?
    Note that the input will be passed to the test harness, so make sure to include proper data format, e.g., http Header.
    Please return Python code to generate five different and diverse inputs and save the ith input in file '{blob_file_prefix}_i.bin' (i from 1 to 5).
    For C projects such as Linux kernel, an input format may be very complicated, for example, 
    '''
4 bytes to indicate the number of commands
[4-bytes command count]

Next there MUST be command count commands. Currently there are two commands: 
 *  0 - sendto() a packet blob
 *      [0x0][4-bytes size][4-bytes send flags][size-bytes packet data]
 *  1 - send netlink packet
        [0x1][4-bytes Message Type][4-bytes Message Flags][4-bytes Netlink Protocol][4-bytes size][size bytes data]
'''

Following is a sample Python code to generate pov.bin:
```python
import struct

NETLINK_GENERIC	= 16

COMMAND_SENDTO 	= 0
COMMAND_NETLINK 	= 1

## Create a sendto command
def compose_sendto_call( flags, pkt_data ):
	data = b''

	data += struct.pack('I', COMMAND_SENDTO)
	data += struct.pack('I', len(pkt_data))
	data += struct.pack('I', flags)
	data += pkt_data

	return data

## Expects a list of blobs
def compose_blob_with_count(cmds):
	data = b''

	data += struct.pack('I', len(cmds))

	for x in cmds:
		data += x

	return data

## Builds a blob for a network packet
def compose_raw_socket_blob(cmds):
	data = b''

	data += compose_blob_with_count(cmds)

	return data

## Builds the blob for a single call to netlink
def compose_netlink_call( nl_msgtype, nl_msgflags, nl_prot, pkt_data):
	data = b''

	data += struct.pack('I', COMMAND_NETLINK)
	data += struct.pack('I', nl_msgtype)
	data += struct.pack('I', nl_msgflags)
	data += struct.pack('I', nl_prot)
	data += struct.pack('I', len(pkt_data))
	data += pkt_data

	return data

if __name__ == '__main__':
	## Compose the blob here
	cmds = []

	packet = b"\x03\x01\x00\x00\x40\x00\x01\x80\x0d\x00\x01\x00\x75\x64\x70\x3a\x55\x44\x50\x31"
	packet += b"\x00\x00\x00\x00\x2c\x00\x04\x80\x14\x00\x01\x00\x02\x00\x17\xe6\x7f\x00\x00\x01"
	packet += b"\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x02\x00\x02\x00\x17\xe6\xe4\x00\x12\x67"
	packet += b"\x00\x00\x00\x00\x00\x00\x00\x00"
	cmds.append( compose_netlink_call(0x1d, 5, NETLINK_GENERIC, packet) )

	packet = b"\x5a\xd0\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x11\x22\x33\x44\x00\x00\x12\x67\x00\x00\x00\x03"
	cmds.append( compose_sendto_call(0, packet) )

	packet = b"\x4f\x40\x00\x38\x20\x00\x00\x00\x00\x00\x80\x00\x11\x22\x33\x44\x00\x00\x00\x01\xc4"
	packet += b"\xd4\x00\x00\x11\x22\x33\x44\x7f\x00\x00\x01\x00\x00\x00\x00\x0d\xac\x00\x00\x55\x44"
	packet += b"\x50\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	cmds.append( compose_sendto_call(0, packet) )

	packet = b"\x4f\x40\x00\x2c\x00\x00\x00\x00\x00\x00\x00\x01\x11\x22\x33\x44\x00\x00\x00\x01"
	packet += b"\xc4\xd4\x00\x00\x11\x22\x33\x44\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
	packet += b"\x00\x00\x00\x00"
	cmds.append( compose_sendto_call(0, packet) )

	packet = b"\x5c\xc0\x03\xf8\x00\x00\x00\x00\x00\x00\x00\x01\x11\x22\x33\x44\x00\x00\x00\x00"
	packet += b"\x00\x00\x00\x00\x48\x41\x58\x58\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	packet += b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\xc4"
	packet += b"\x43"*956

	cmds.append( compose_sendto_call(0, packet) )

	blob = compose_raw_socket_blob( cmds )

	## Write out the blob
	f = open('pov.bin', 'wb')
	f.write(blob)
	f.close()
```
The sample POV file for Linux kernel contains {sample_linux_content}
"""
    with open(harness_source, "r") as file:
        prompt_harness_data = file.read()

    full_prompt_harness = prompt_harness_pre + prompt_harness_data
    messages.append({"content": full_prompt_harness, "role": "user"})
    harness_gpt4_result = call_llm(messages)
    print(harness_gpt4_result)  
    try:         
        python_code = extract_python_code(harness_gpt4_result)
        python_code_cleaned = python_code.strip('```python\n').strip('```\n')
        exec_clean_python_code(python_code_cleaned)
    except Exception as e:
        print(f"TODO: an unexpected error occurred in generate_povs_for_harness_c_linux: {e}")
        # return '', ''
    # the above should have created 'pov_i.bin'
    for i in range(5):
        x = i+1
        blob_file_i = f"{blob_file_prefix}_{x}.bin"
        print(f"checking POV {blob_file_i}")
        sanitizer_id = run_pov(harness_name,blob_file_i)
        if len(sanitizer_id)>0:
            shutil.copy(blob_file_i, blob_file)
            sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)

        if len(sanitizer_id)>0:
            print(f"successful POV generate_povs_for_harness_c_linux: {blob_file_i}")
            #copy blob_file_i to blob_file
            return sanitizer_id, harness_gpt4_result

    # TODO try fuzz w/ the sample pov
    if os.path.exists(sample_blob_file_name): 
        # TODO use llm to generate 10 variants of sample_pov
        messages.append({"content": harness_gpt4_result, "role": "assistant"})
        blob_file_prefix_sample = f"{blob_file_prefix}_sample"
        final_prompt_harness = f"Unfortunately, all POVs generated by your script failed. Can you give it a final try? Return Python code to generate ten different and diverse variants of the sample POV and save the ith input in file '{blob_file_prefix_sample}_i.bin' (i from 1 to 10)."
        messages.append({"content": final_prompt_harness, "role": "user"})
        harness_gpt4_result = call_llm(messages)
        print(harness_gpt4_result)  
        try:         
            python_code = extract_python_code(harness_gpt4_result)
            python_code_cleaned = python_code.strip('```python\n').strip('```\n')
            exec_clean_python_code(python_code_cleaned)
        except Exception as e:
            print(f"TODO final: an unexpected error occurred in generate_povs_for_harness_c_linux: {e}")

        for i in range(10):
            x = i+1
            blob_file_i = f"{blob_file_prefix_sample}_{x}.bin"
            print(f"checking final POV {blob_file_i}")
            sanitizer_id = run_pov(harness_name,blob_file_i)
            if len(sanitizer_id)>0:
                shutil.copy(blob_file_i, blob_file)
                sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)

            if len(sanitizer_id)>0:
                print(f"final successful POV generate_povs_for_harness_c_linux: {blob_file_i}")
                #copy blob_file_i to blob_file
                return sanitizer_id, harness_gpt4_result
        
        #final: use sample.bin itself
        sanitizer_id = run_pov(harness_name,sample_blob_file_name)
        if len(sanitizer_id)>0:
            shutil.copy(sample_blob_file_name, blob_file)
            sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)
        if len(sanitizer_id)>0:
            print(f"successful POV generate_povs_for_harness_c_linux w/ sample: {sample_blob_file_name}")
            #copy blob_file_i to blob_file
            return sanitizer_id, harness_gpt4_result

    return '', ''

def generate_povs_for_harness_c_other(harness_id:str,harness_name:str,harness_source:str,blob_file:str,messages) -> (str, str):
    blob_file_prefix = blob_file.split('.bin')[0]
    sample_mock1_content = """abcdefabcdefabcdefabcdefabcdefabcdef
b

1
"""
    sample_mock2_content = """ab
b

501
"""
    sample_nginx_content = """GET / HTTP/1.1
Host: localhost
Cookie: uid=YWFhYWFhYWFhYWFhYWFhYWJiYmJiYmJiYmJiYmJiYmJjY2NjY2NjY2NjY2NjY2Njaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;
"""
    sample_mock1_blob_file_name = 'sample_mock1.bin'
    sample_mock2_blob_file_name = 'sample_mock2.bin'
    sample_nginx_blob_file_name = 'sample_nginx.bin'

    if os.path.exists(sample_mock1_blob_file_name):
        with open(sample_mock1_blob_file_name, 'rb') as file:
            sample_mock1_content = file.read()
    if os.path.exists(sample_mock2_blob_file_name):
        with open(sample_mock2_blob_file_name, 'rb') as file:
            sample_mock2_content = file.read()
    if os.path.exists(sample_nginx_blob_file_name):
        with open(sample_nginx_blob_file_name, 'rb') as file:
            sample_nginx_content = file.read()

    prompt_harness_pre=f"""Thanks! You are an expert in software security testing. I have a test harness below.
    Can you generate an input that could exploit the potential vulnerability using the given test harness?
    Note that the input will be passed to the test harness, so make sure to include proper data format, e.g., http Header.
    Please return Python code to generate five different and diverse inputs and save the ith input in file '{blob_file_prefix}_i.bin' (i from 1 to 5) .
    Here are some examples:
    mock_cp1: {sample_mock1_content}
    mock_cp2: {sample_mock2_content}
    nginx: {sample_nginx_content}
    """
    with open(harness_source, "r") as file:
        prompt_harness_data = file.read()

    full_prompt_harness = prompt_harness_pre + prompt_harness_data
    messages.append({"content": full_prompt_harness, "role": "user"})
    harness_gpt4_result = call_llm(messages)
    print(harness_gpt4_result)  
    try:         
        python_code = extract_python_code(harness_gpt4_result)
        python_code_cleaned = python_code.strip('```python\n').strip('```\n')
        exec_clean_python_code(python_code_cleaned)
    except Exception as e:
        print(f"TODO: an unexpected error occurred in generate_povs_for_harness_c_other: {e}")
        # return '', ''
    # the above should have created 'pov_i.bin'
    for i in range(5):
        x = i+1
        blob_file_i = f"{blob_file_prefix}_{x}.bin"
        print(f"checking POV {blob_file_i}")
        sanitizer_id = run_pov(harness_name,blob_file_i)
        if len(sanitizer_id)>0:
            shutil.copy(blob_file_i, blob_file)
            sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)

        if len(sanitizer_id)>0:
            print(f"successful POV generate_povs_for_harness_c_other: {blob_file_i}")
            #copy blob_file_i to blob_file
            return sanitizer_id, harness_gpt4_result    

    # TODO try fuzz w/ the sample pov
    sample_blob_file_name = sample_nginx_blob_file_name
    if os.path.exists(sample_blob_file_name): 
        # TODO use llm to generate 10 variants of sample_pov
        messages.append({"content": harness_gpt4_result, "role": "assistant"})
        blob_file_prefix_sample = f"{blob_file_prefix}_sample"
        final_prompt_harness = f"Unfortunately, all POVs generated by your script failed. Can you give it a final try? Return Python code to generate ten different and diverse variants of the sample POV and save the ith input in file '{blob_file_prefix_sample}_i.bin' (i from 1 to 10)."
        messages.append({"content": final_prompt_harness, "role": "user"})
        harness_gpt4_result = call_llm(messages)
        print(harness_gpt4_result)  
        try:         
            python_code = extract_python_code(harness_gpt4_result)
            python_code_cleaned = python_code.strip('```python\n').strip('```\n')
            exec_clean_python_code(python_code_cleaned)
        except Exception as e:
            print(f"TODO final: an unexpected error occurred in generate_povs_for_harness_c_other: {e}")

        for i in range(10):
            x = i+1
            blob_file_i = f"{blob_file_prefix_sample}_{x}.bin"
            print(f"checking final POV {blob_file_i}")
            sanitizer_id = run_pov(harness_name,blob_file_i)
            if len(sanitizer_id)>0:
                shutil.copy(blob_file_i, blob_file)
                sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)

            if len(sanitizer_id)>0:
                print(f"final successful POV generate_povs_for_harness_c_other: {blob_file_i}")
                #copy blob_file_i to blob_file
                return sanitizer_id, harness_gpt4_result
        
        #final: use sample.bin itself
        sanitizer_id = run_pov(harness_name,sample_blob_file_name)
        if len(sanitizer_id)>0:
            shutil.copy(sample_blob_file_name, blob_file)
            sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)

        if len(sanitizer_id)>0:
            print(f"successful POV generate_povs_for_harness_c_other w/ sample: {sample_blob_file_name}")
            #copy blob_file_i to blob_file
            return sanitizer_id, harness_gpt4_result

    return '', ''

def check_and_update_current_line(line:str,modified_content,current_line) -> int:
    line_x1 = line[1:].strip()
    line_x2 = modified_content[current_line].strip()
    print(f"line_x1:{line_x1}")
    print(f"line_x2:{line_x2}")
    if line_x1 != line_x2:
        print(f"Correct current_line by search backwards and forwards")
        # TODO Make sure it matches

        # Flag to indicate if a match is found
        match_found = False
        # Iterate through the range of +-5 lines
        for distance in range(1, 10):
            for offset in (-distance, distance):
                current_line_x = current_line + offset
                # Ensure the line index is within valid range
                if 0 <= current_line_x < len(modified_content):
                    line_x2 = modified_content[current_line_x].strip()
                    if line_x1 == line_x2:
                        return current_line_x

        # Optional: handle the case when no match is found
        if not match_found:
            print("No match found within the range of +-10 lines.")
    return current_line

def parse_and_apply_diff(diff_content):
    file_path = re.search(r'--- a/(.+)', diff_content).group(1)
    if file_path is None:
        file_path = re.search(r'+++ a/(.+)', diff_content).group(1)

    # Read the original file
    with open(file_path, 'r') as file:
        original_content = file.readlines()

    # Parse the diff and apply changes
    modified_content = original_content.copy()
    diff_lines = diff_content.split('\n')

    # Find the starting line number for changes
    start_line = 0
    for line in diff_lines:
        if line.startswith('@@'):
            match = re.search(r'-(\d+),(\d+)', line)
            if match:
                start_line = int(match.group(1)) - 1
                break
    print(f"start_line:{start_line}")
    # Apply changes
    current_line = start_line
    for line in diff_lines:
        print(f"current_line:{current_line}")
        print(f"line:{line}")
        if line.startswith('---') or line.startswith('+++') or line.startswith('diff') or line.startswith('index'):
            continue
        elif line.startswith('@@'):
            match = re.search(r'-(\d+),(\d+)', line)
            if match:
                current_line = int(match.group(1))
        else:
            if line.startswith('-'):
                current_line = check_and_update_current_line(line,modified_content,current_line)
                # Remove line
                print(f"Removed:{modified_content[current_line]}")
                del modified_content[current_line]
            elif line.startswith('+'):
                # Add line
                modified_content.insert(current_line, line[1:] + '\n')
                current_line += 1
            else:
                # Unchanged line
                current_line += 1

    # Write the modified content back to the file
    with open(file_path, 'w') as file:
        file.writelines(modified_content)

def generate_and_test_patch(commit_id:str,harness_name:str,blob_file:str, messages) -> (bool, str):

    prompt_patch_pre=f"""Thanks! Your test input is successful. Can you generate a patch to fix the vulnerability introduced in Commit {commit_id}?
The patch must be in the unified diff format. Minimize the patch size, and do not include comments. Make sure that the starting line number and the number of lines in each hunk are correct. Make sure the lines from the original file are matched exactly, including the number of heading spaces. Mark the fixed patch by ```diff and ```.
"""
    full_prompt_patch = prompt_patch_pre 
    messages.append({"content": full_prompt_patch, "role": "user"})
    # print(f"generate_and_test_patch messages:\n{messages}")  

    blob_x = blob_file.split('_')[1].split('.')[0]

    for i in range(TRY_PATCH_TIMES):
        x = i+1
        patch_file = f"patch_{blob_x}_{x}.diff"
        patch_file_path = os.path.join(os.getcwd(), patch_file)
        # debug detected dubious ownership in repository at '/crs_scratch/patch_8e2a/nginx-cp/src/nginx'
        # patch_file_path = remove_second_segment(patch_file_path)

        print(f"\n\nPatch iteration {x} patch_file: {patch_file}")
        
        patch_gpt4_result = call_llm_for_patch(messages)
        print(patch_gpt4_result)  

        messages.append({"content": patch_gpt4_result, "role": "assistant"})

        try:         
            patch_diff = extract_diff_for_patch(patch_gpt4_result)+"\n"
            print(f"\nExtracted patch:\n\n{patch_diff}")

            # number_of_files, number_of_hunks = count_files_and_hunks(patch_diff)
            # print(f"Patch number_of_files: {number_of_files}")
            # print(f"Patch number_of_hunks: {number_of_hunks}")

            diff_infos = extract_diff_info(patch_diff)
            print(f"diff_info number_of_files: {len(diff_infos)}")
            for file_info in diff_infos:
                print(f"Modified File: {file_info['file']}")
                for hunk in file_info['hunks']:
                    print(f"  Hunk (lines {hunk['start_line_number']} to {hunk['end_line_number']}):")
                    for line in hunk['hunk_lines']:
                        print(f"    {line}")

            # TODO handle multiple files
            diff_info = diff_infos[0]
            file_path = diff_info["file"]
            cp_source = find_cp_source_name(file_path)
            #save to patch_file
            with open(patch_file, 'w') as file:
                file.write(patch_diff)
            # if successful, this may take a long time because it also builds the source
            patch_success,output = apply_patch(patch_file)

            if patch_success == False:
                print(f"Try again to correct patch content")
                patch_diff = correct_patch_content(patch_diff,file_path, cp_source, diff_info, output)
                with open(patch_file, 'w') as file:
                    file.write(patch_diff)
                patch_success,output = apply_patch(patch_file)
            
            patch_valid = False
            if patch_success == True:
                patch_valid,output = validate_patch(harness_name,blob_file)
            else:
                print(f"LLM-generated patch {patch_file_path} failed. Let's try manual parsing and editing")
                
                current_cp_directory = os.getcwd()
                source_file_path = os.path.join(current_cp_directory, 'src/'+cp_source)
                os.chdir(source_file_path)
                try:
                    # Parse the diff and apply the changes
                    parse_and_apply_diff(patch_diff.strip())

                    # generate patch diff and save it to patch_file_path
                    result = subprocess.run(['git', 'diff'], capture_output=True, text=True)
                    with open(patch_file_path, 'w') as patch_file:
                        patch_file.write(result.stdout)
                except Exception as e:
                    print(f"Failed to do manual patch: {e}")
                    
                os.chdir(current_cp_directory)
                #build
                try:
                    subprocess.run(['./run.sh', '-x', 'build'])
                    patch_valid,output = validate_patch(harness_name,blob_file)
                    print(f"Manual edit patch is valid: {patch_valid} output: {output}")
                except Exception as e:
                    print(f"Failed to build the manual patched program: {e}")    
            
            # either patch_success or not, recover to HEAD
            subprocess.run(['git', '-C', 'src/'+cp_source, 'reset', '--hard', 'HEAD'])
            
            if patch_valid == True:
                print(f"Success: {patch_file_path} is valid!!!")
                return True, patch_file_path
            else:
                print(f"Fail: {patch_file_path} is invalid! Error: {output}")
                prompt_refined = f"""The patch generated above does not work. Here is the error message: {output}
                                Can you please try again?
                                """
                messages.append({"content": prompt_refined, "role": "user"})

        except Exception as e:
                print(f"An unexpected error occurred: {e}")

    return False, 'All patches failed'

# check out all sources and build
if False:
    print(f"Building the initial project from HEAD")
    reset_head_and_build()

# Open and read the file
with open('commits.txt', 'r') as file:
    # Traverse each line in the file
    for line in file:
        # Strip any leading/trailing whitespace
        commit_file = line.strip()
        # for testing only
        TESTING = False
        # TESTING = True
        know_vulnerable_linux_commit_file = "747400b971e2131ef86fbab1aa6350f181e40310.txt"
        know_vulnerable = (commit_file == know_vulnerable_linux_commit_file)
        if TESTING and commit_file != know_vulnerable_linux_commit_file:
            continue
        if len(target_commit_file) > 0 and commit_file != target_commit_file:
            continue
        
        commit_id = commit_file.strip('.txt')
        short_commit_id = commit_id[:4]

        messages = []
        commit_gpt4_result = check_commit(cp_name,commit_file,messages)
        # if True:
        #     continue

        commit_gpt4_result_lower = commit_gpt4_result.lower()
        if know_vulnerable or 'result: yes context only' not in commit_gpt4_result_lower and 'result: no' not in commit_gpt4_result_lower and len(commit_gpt4_result_lower) > 100:
        #TODO: check if commit_gpt4_result indicates a vulnerability
        # if 'Result: YES context only' not in commit_gpt4_result and 'Result: No' not in commit_gpt4_result and len(commit_gpt4_result) > 100:
            messages.append({"content": commit_gpt4_result, "role": "assistant"})

            patch_successful = False

            for harness_id, harness_info in harnesses.items():
                harness_name = harness_info.get('name')
                harness_source = harness_info.get('source')
                if patch_successful == True:
                    break

                # Generate POVs for the harness
                blob_file = f"pov_{short_commit_id}.bin"
                # for testing
                # if True:
                #     messages_pov_copy = messages.copy()
                #     generate_povs_for_harness_java(harness_id,harness_name,harness_source,blob_file,messages_pov_copy)
                #     continue

                # TODO: try 10 times until success
                sanitizer_id = ''
                for i in range(TRY_POV_TIMES):
                    x = i+1
                    print(f"\n\nPOV iteration {x}")
                    messages_pov_copy = messages.copy()
                    harness_gpt4_result = generate_povs_for_harness(harness_id,harness_name,harness_source,blob_file,messages_pov_copy)
                    sanitizer_id = run_pov(harness_name,blob_file)
                    if len(sanitizer_id)>0: 
                        sanitizer_id = validate_pov(sanitizer_id,commit_id,harness_name,blob_file)
                        if len(sanitizer_id)>0:  
                            break

                if len(sanitizer_id) == 0:
                    print(f"POV special handling {language} for {cp_name}")
                    messages_pov_copy = messages.copy()
                    # special handling for Java 
                    if language == 'java' or language == 'Java':
                        sanitizer_id, harness_gpt4_result  = generate_povs_for_harness_java(harness_id,harness_name,harness_source,blob_file,messages_pov_copy)
                    elif language == 'c' and cp_name == 'linux kernel':
                        sanitizer_id, harness_gpt4_result  = generate_povs_for_harness_c_linux(harness_id,harness_name,harness_source,blob_file,messages_pov_copy)
                    else:
                        sanitizer_id, harness_gpt4_result  = generate_povs_for_harness_c_other(harness_id,harness_name,harness_source,blob_file,messages_pov_copy)
                        

                #TODO if the sample POV fails, try generate 100 diverse POVs based on it to fuzz more
                if len(sanitizer_id)>0: 
                    messages_patch_copy = messages_pov_copy
                    messages_patch_copy.append({"content": harness_gpt4_result, "role": "assistant"})
                    # harness_id = 'id_1'
                    # sanitizer_id = 'id_1'
                    vds_status = submit_vds(cp_name,commit_id,sanitizer_id,harness_id,blob_file)
                    if vds_status['status'] == 'rejected':
                        print(f"Our VDS for {commit_id} was rejected, so we've got to start over.")
                    elif vds_status['status'] == 'duplicated':
                        print(f"Our VDS for {commit_id} was duplicated, so we just skip.")
                    else:
                        print("Our VDS was accepted, so we should move on to producing a Generated Patch (GP).")
                        with open(done_pov_file_path, 'a') as file:
                            file.write(commit_file+'\n')

                        cpv_uuid = vds_status['cpv_uuid']

                        # Generate patch
                        # patch_file = 'patch_x.diff'
                        if CP_ROOT != None:
                            # TODO: create a new directory "patch_'commit_id'" for the cp
                            base_dir, cp = os.path.split(current_cp_directory_x)
                            patch_directory = f"{base_dir}/patch_{short_commit_id}/"
                            patch_cp_path = os.path.join(patch_directory, cp)
                            print(f"Copy cp to scratch patch {patch_cp_path}")
                            src = os.path.join(CP_ROOT, cp)
                            dest = patch_directory
                            subprocess.run(['rsync', '--archive', '--delete', src, dest])
                            # copy blob_file and enter the new directory, 
                            shutil.copy(blob_file, patch_cp_path)
                            os.chdir(patch_cp_path)
                            user, group = get_current_user_and_group()
                            patch_cp_path_src = patch_cp_path+'/src/'
                            cp_sources = project_yaml.get('cp_sources', {})
                            for source_name, details in cp_sources.items():
                                repo_path_source = os.path.join(patch_cp_path_src, source_name)
                                change_ownership_and_permissions(repo_path_source,user,group)
                                subprocess.run(["git", "config", "--add", "safe.directory", repo_path_source])

                        # in multithreaded model, this should run until success or timeout
                        while True:
                            if os.path.exists(done_gp_file_path):
                                with open(done_gp_file_path, 'r') as file:
                                    done_gps = file.read()
                                    if done_gps.count(commit_file) > 0:
                                        print(f"Patching: skipped {commit_file} because it has been successfully patched!")
                                        os.chdir(current_cp_directory_x)
                                        patch_successful = True
                                        break

                            messages_patch_copy_x = messages_patch_copy
                            patch_valid, patch_file = generate_and_test_patch(commit_id,harness_name,blob_file,messages_patch_copy_x)
                            if patch_valid == True:                            
                                # if Patch successful, submit

                                # Read the content of the file
                                with open(patch_file, 'rb') as file:
                                    llm_response_patch = file.read()
                                # Encode the content in base64
                                patch_b64 = base64.b64encode(llm_response_patch).decode('utf-8')

                                gp_data = {
                                    "cpv_uuid": cpv_uuid,
                                    "data": patch_b64
                                }

                                #check rejected duplication
                                rejected_gp_file_path = f"rejected_gp_{commit_id}.txt"
                                hash_hex = compute_hash_hex(gp_data)
                                if os.path.exists(rejected_gp_file_path):
                                    with open(rejected_gp_file_path, 'r') as file:
                                        rejected_gps = file.read()
                                        # if hash_hex already rejected, then return 
                                        if rejected_gps.count(hash_hex) > 0:
                                            print("duplicated rejected submission, avoided!")
                                            continue

                                gp_response = make_request('POST', 'submission/gp/', gp_data)
                                print(json.dumps(gp_response, indent=2))

                                gp_uuid = gp_response['gp_uuid']
                                print("\nNow we wait while the cAPI evaluates our GP.\n")
                                while True:
                                    gp_status = make_request('GET', f'submission/gp/{gp_uuid}')
                                    print(json.dumps(gp_status, indent=2))
                                    if gp_status['status'] != 'pending':
                                        break
                                    time.sleep(10)
                                    print("Waiting for GP to finish testing...\n")

                                print("\nThe cAPI has finished testing our GP. As with the VDS, our GP could be accepted or rejected at this point.")
                                print("Final GP Status: {}".format(gp_status['status']))
                                if gp_status['status'] == 'rejected':
                                    print(f"Patch was rejected unfortunately... TODO use fuzz to verify")
                                    with open(rejected_gp_file_path, 'a') as file:
                                        file.write(hash_hex+'\n')
                                else:
                                    with open(done_gp_file_path, 'a') as file:
                                        file.write(commit_file+'\n')
                                    # Change to the CP directory and return to the thread pool 
                                    os.chdir(current_cp_directory_x)
                                    patch_successful = True
                                    break
                            if patch_successful != True:   
                                print(f"Loop again... tried generate_and_test_patch, but failed to patch the vulnerability for commit {commit_id}\n")
        else:
            #no vulnerability found, skip this commit
            print(f"No vulnerability found in commit {commit_file}")
            with open(no_vul_file_path, 'a') as file:
                file.write(commit_file+'\n')
