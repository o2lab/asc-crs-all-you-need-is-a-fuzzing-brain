import os
import time
import requests
import base64
import tempfile
import subprocess
import yaml
import json

# Define constants
CAPI_HOSTNAME = os.getenv('AIXCC_API_HOSTNAME')
CRS_SCRATCH_SPACE = os.getenv('AIXCC_CRS_SCRATCH_SPACE')
CP_ROOT = os.getenv('AIXCC_CP_ROOT')
LITELLM_HOSTNAME = os.getenv('AIXCC_LITELLM_HOSTNAME')
LITELLM_KEY = os.getenv('LITELLM_KEY')
AUTH = ('00000000-0000-0000-0000-000000000000', 'secret')

# Function to make cAPI request
def make_request(method, endpoint, data=None):
    url = f"{CAPI_HOSTNAME}/{endpoint}"
    response = requests.request(method, url, auth=AUTH, json=data)
    return response.json()

# Check if cAPI is available
print("PYTHON The following is a demonstration of a fake CRS interacting with the competition API (cAPI). First, we'll make sure the cAPI is available.")
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

# Copy CPs to scratch space
print("\nIn this example, we're using an example challenge problem vulnerability (CPV) in the Mock CP, so we already know the answers.")
print("But to demonstrate, let's copy to our scratch space like we would normally.\n")
for cp in os.listdir(CP_ROOT):
    src = os.path.join(CP_ROOT, cp)
    dest = CRS_SCRATCH_SPACE
    subprocess.run(['rsync', '--archive', '--delete', src, dest])

# Change to CP folder
print("\nWhile there may be multiple CPs in {}, we're going to go ahead and just do the Mock CP here.".format(CP_ROOT))
cp_folder = os.path.join(CRS_SCRATCH_SPACE, 'mock-cp')
os.chdir(cp_folder)

# Read project.yaml
with open('project.yaml', 'r') as file:
    project_yaml = yaml.safe_load(file)

print("CPs have sources, which is where the vulnerabilities actually exist. Mock CP has these:\n")
print(json.dumps(project_yaml['cp_sources'], indent=2))

source_dir = list(project_yaml['cp_sources'].keys())[0]
src_folder = os.path.join(cp_folder, 'src', source_dir)
print("\nSome CPs may have multiple sources. The Mock CP has only one source, in {}.".format(source_dir))
print("At this point, a real CRS might send parts of the CP's sources off to LiteLLM ({} using the credential {}).".format(LITELLM_HOSTNAME, LITELLM_KEY))

# Assume LLM & CRS have produced these values
llm_response_commit = '9d38fc63bb9ffbc65f976cbca45e096bad3b30e1'
llm_response_blob = "abcdefabcdefabcdefabcdefabcdefabcdef\nb\n\n1\n"
llm_response_harness = 'stdin_harness.sh'
llm_response_sanitizer = "AddressSanitizer: global-buffer-overflow"

print("Then it would test the responses using the local copy of the CP.\n")

with tempfile.NamedTemporaryFile(delete=False) as blob_file:
    blob_file.write(llm_response_blob.encode())

os.chdir(src_folder)
subprocess.run(['git', 'checkout', llm_response_commit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
os.chdir(cp_folder)
subprocess.run(['./run.sh', 'build'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Test blob with harness and check if the sanitizer fired
result = subprocess.run(['./run.sh', 'run_pov', blob_file.name, llm_response_harness], capture_output=True, text=True)
pov_output = result.stdout + result.stderr

if llm_response_sanitizer in pov_output:
    print("\nLooks like our sanitizer fired, as expected.")
else:
    print("\nOur sanitizer did not fire, so we've got to start all over.")
    exit(1)

# Submit VDS
print("Now that we've confirmed that our VDS works, let's submit it.")
print("Using the contents of the CP's project.yaml, we can convert our harness & sanitizer to the CP's canonical names.\n")

harness_id = next(key for key, value in project_yaml['harnesses'].items() if value['name'] == llm_response_harness)
sanitizer_id = next(key for key, value in project_yaml['sanitizers'].items() if value == llm_response_sanitizer)

b64_blob = base64.b64encode(llm_response_blob.encode()).decode()
vds_data = {
    "cp_name": "Mock CP",
    "pou": {
        "commit_sha1": llm_response_commit,
        "sanitizer": sanitizer_id
    },
    "pov": {
        "harness": harness_id,
        "data": b64_blob
    }
}

print("\nNow that we have the inputs we need for the API, we can go ahead and submit our VDS.\n")
vds_response = make_request('POST', 'submission/vds/', vds_data)
print(json.dumps(vds_response, indent=2))

vds_uuid = vds_response['vd_uuid']
print("\nThe cAPI is now evaluating our Vulnerability Discovery Submission (VDS). Its status will be pending until the cAPI runs all the tests.\n")

while True:
    vds_status = make_request('GET', f'submission/vds/{vds_uuid}')
    print(json.dumps(vds_status, indent=2))
    if vds_status['status'] != 'pending':
        break
    time.sleep(10)
    print("\nWaiting for VDS to finish testing...\n")

print("\nAt this point, the VDS has been fully tested. It could either be accepted or rejected.")
if vds_status['status'] == 'rejected':
    print("Our VDS was rejected, so we've got to start over.")
    exit(1)

print("Our VDS was accepted, so we should move on to producing a Generated Patch (GP).")
print("A real CRS would be asking an LLM to produce a patch file now.")

# Assume LLM & CRS have produced this patch
llm_response_patch = """\
diff --git a/mock_vp.c b/mock_vp.c
index 56cf8fd..abb73cd 100644
--- a/mock_vp.c
+++ b/mock_vp.c
@@ -11,7 +11,8 @@ int main()
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 9, stdin);
+        if (i==3){buff[0]= 0;}
         buff[strcspn(buff, "\\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
"""

cpv_uuid = vds_status['cpv_uuid']
print("We need that CPV UUID from the last status response, which the cAPI assigned to us. Looks like it's {}.".format(cpv_uuid))
print("Now that we've got our CPV UUID and our patch, let's submit it.\n")

patch_b64 = base64.b64encode(llm_response_patch.encode()).decode()
gp_data = {
    "cpv_uuid": cpv_uuid,
    "data": patch_b64
}

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
print("For more information on what was done here, there are logs available in docker-compose, as well as an audit log that the cAPI produced.")
print("Look at the outputs of `make logs-nofollow` (for all the services) and `make logs-crs-nofollow` (for the CRS's logs only).")
print("There are a few other make targets available to show you logs for crs-sandbox, including `make logs-capi-audit`.")
