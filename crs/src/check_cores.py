import typing
import multiprocessing
import math

from pathlib import Path

def get_cpu_cores_via_cgroups() -> typing.Optional[int]:
    # cgroups V1
    cfs_period_path = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
    cfs_quota_path = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
    # cgroups V2
    cpu_max_path = "/sys/fs/cgroup/cpu.max"
    cpu_cores = _get_cpu_cores(cfs_period_path, cfs_quota_path, cpu_max_path)
    return cpu_cores

def _get_cpu_cores(cfs_period_path: str, cfs_quota_path: str, cpu_max_path: str) -> typing.Optional[int]:
    cpu_cores = None
    cfs_period = Path(cfs_period_path)
    cfs_quota = Path(cfs_quota_path)
    if cfs_period.exists() and cfs_quota.exists():
        with cfs_period.open("rb") as fp_p, cfs_quota.open("rb") as fp_q:  # we are in a linux container with cpu quotas!
            p, q = int(fp_p.read()), int(fp_q.read())
            # get the cores allocated by dividing the quota in microseconds by the period in microseconds
            cpu_cores = math.ceil(q / p) if q > 0 and p > 0 else None
    else:
        cpu_max = Path(cpu_max_path)
        if cpu_max.exists():
            line = cpu_max.read_text()
            cpu_cores = cpu_cores_from_cgroups_v2_cpu_max(line)
    return cpu_cores
def cpu_cores_from_cgroups_v2_cpu_max(line: str) -> typing.Optional[int]:
    cpu_cores = None
    parts = line.split(" ")
    if len(parts) == 2:
        # Check whether there is no limit set for CPU
        if parts[0] == "max":
            return multiprocessing.cpu_count()
        # The first value is the allowed time quota in microseconds for which all processes collectively in
        # a child group can run during one period.
        q = int(parts[0])
        # The second value specifies the length of the period.
        p = int(parts[1])
        cpu_cores = math.ceil(q / p) if q > 0 and p > 0 else None
    return cpu_cores

if __name__ == "__main__":
    cores = get_cpu_cores_via_cgroups()
    print(f'{cores} cores')
