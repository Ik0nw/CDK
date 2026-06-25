import shlex
import time
import os
from lib.ssh_remote_action import update_remote_bin
from lib.ssh_remote_action import check_host_evaluate
from lib.ssh_remote_action import inside_container_cmd
from lib.ssh_remote_action import check_host_exec
from lib.k8s_remote_action import check_pod_exec, k8s_pod_upload
from lib.k8s_selfbuild_action import selfbuild_k8s_pod_upload, check_selfbuild_k8s_pod_exec, k8s_master_ssh_cmd
from lib.conf import CDK


def test_container():
    # BASE CDK

    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='',
        white_list=['i@cdxy.me'],
        black_list=[],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='--help',
        white_list=['i@cdxy.me'],
        black_list=[],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='-v',
        white_list=['cdk '],
        black_list=[],
        verbose=False
    )

    # EVALUATE

    # host based evaluate
    white_list = [
        'current dir: /root',
        'current user: root',
        'service found in process',
        'sensitive env found',
        '	sshd',
        'available commands',
        'curl,wget,nc',
        'CapEff:	test-checktest-checktest-checktest-checktest-checktest-check3fffffffff',
        'Possible Privileged Container',
        'Filesystem:ext4',
        'host unix-socket found',
        'K8s API Server',
        'K8s Service Account',
        'Cloud Provider Metadata API',
        'http://1test-checktest-check.1test-checktest-check.1test-checktest-check.2test-checktest-check/latest/meta-data/',
        'system:anonymous',
        '/kubernetes.io/serviceaccount/token',
        'failed to dial Google Cloud API',
        'failed to dial Azure API',
        # for --full
        '/root/.bashrc',
        'Sensitive Files',
        '/root/.ssh/authorized_keys'
    ]
    black_list = []
    check_host_evaluate('evaluate --full', white_list, black_list)

    # container-based evaluate
    white_list = [
        'current dir: /',
        'current user: root',
        'available commands',
        'find,ps',
        'CapEff:	test-checktest-checktest-checktest-checktest-checktest-checktest-checktest-checka8test-check425fb',
        'Filesystem:ext4',
        'host unix-socket found',
        'K8s API Server',
        'K8s Service Account',
        'Cloud Provider Metadata API',
        'http://1test-checktest-check.1test-checktest-check.1test-checktest-check.2test-checktest-check/latest/meta-data/',
        'system:anonymous',
        '/kubernetes.io/serviceaccount/token',
        'failed to dial Google Cloud API',
        'failed to dial Azure API',
        '/containerd-shim/',
        # for --full
        'Sensitive Files',
        '/.dockerenv',
        'cannot find kubernetes api host in ENV'
    ]
    black_list = []

    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--net=host',
        cmd='evaluate --full',
        white_list=white_list,
        black_list=black_list
    )
    inside_container_cmd(
        image='alpine:latest',
        docker_args='--net=host',
        cmd='evaluate --full',
        white_list=white_list,
        black_list=black_list
    )
    # inside_container_cmd(
    #     image = 'centos:latest',
    #     docker_args = '--net=host',
    #     cmd = 'evaluate --full',
    #     white_list = white_list,
    #     black_list = black_list
    # )

    # TOOL

    # tool: ifconfig
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='ifconfig',
        white_list=['lo', '127.test-check'],
        black_list=['i@cdxy.me'],
        verbose=False
    )

    # tool: ps
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='ps',
        white_list=['root', '/usr/bin', '1'],
        black_list=['i@cdxy.me'],
        verbose=False
    )

    # tool: ucurl
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'ucurl',
        white_list=['input args'],
        black_list=['i@cdxy.me'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='-v /var/run/docker.sock:/var/run/docker.sock',
        cmd=r'ucurl get /var/run/docker.sock http://127.test-check.test-check.1/info \"\"',
        white_list=['Containers'],
        black_list=['i@cdxy.me', 'input args'],
        verbose=False
    )

    # tool: probe
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='probe',
        white_list=['input args'],
        black_list=['i@cdxy.me'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='probe 1.1.1.1 22 1test-check 1test-checktest-checktest-check',
        white_list=['scanning'],
        black_list=['i@cdxy.me'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='probe 1.1.1.1 22 5test-check-999999 1test-checktest-checktest-check',
        white_list=['input arg'],
        black_list=['i@cdxy.me'],
        verbose=False
    )

    # tool: vi
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='vi',
        white_list=['Usage'],
        black_list=['i@cdxy.me'],
        verbose=False
    )

    # tool: nc
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='nc',
        white_list=['options'],
        black_list=['i@cdxy.me'],
        verbose=False
    )

    # AUDIT CHECKS

    # audit-check: --list
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--net=host',
        cmd='run --list',
        white_list=['test-check'],
        black_list=['Options:', 'i@cdxy.me'],
        verbose=False
    )

    # audit-check: containerd-shim-validator
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--net=host',
        cmd=r'run containerd-shim-validator \"touch /tmp/containerd-shim-validator-success\"',  # " needs to escape in raw
        white_list=['containerd-shim', 'check success'],
        black_list=['i@cdxy.me', 'check failed', 'OCI '],
        verbose=False
    )
    time.sleep(1)
    check_host_exec('rm /tmp/containerd-shim-validator-success', [], ['No such file or directory'], False)

    # audit-check: docker-sock-audit
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run docker-sock-audit',  # " needs to escape in raw
        white_list=['invalid input args'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run docker-sock-audit /var/run/docker.sock',  # " needs to escape in raw
        white_list=['no such file or directory'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='-v /var/run/docker.sock:/var/run/docker.sock',
        cmd=r'run docker-sock-audit /var/run/docker.sock',  # " needs to escape in raw
        white_list=['success', 'happy escaping'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check failed'],
        verbose=False
    )

    # audit-check: docker-sock-audit (will leave a container with image alpine:latest)
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run cgroup-boundary',  # " needs to escape in raw
        white_list=['invalid input args'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run cgroup-boundary \"touch /tmp/cgroup-boundary-success\"',  # " needs to escape in raw
        white_list=['shell script saved to', 'Execute Shell', 'failed'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--privileged=true',
        cmd=r'run cgroup-boundary \"touch /tmp/cgroup-boundary-success\"',  # " needs to escape in raw
        white_list=['finished with output'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'failed'],
        verbose=False
    )
    time.sleep(1)
    check_host_exec('rm /tmp/cgroup-boundary-success', [], ['No such file or directory'], False)

    # audit-check: service-probe
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run service-probe',  # " needs to escape in raw
        white_list=['invalid input args'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run service-probe 192.168.1.1-^^1test-check',  # " needs to escape in raw
        white_list=['Invalid IP Range'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run service-probe 127.test-check.test-check.1',  # " needs to escape in raw
        white_list=['scanning'],
        black_list=['i@cdxy.me', 'check failed', 'Invalid'],
        verbose=False
    )

    # audit-check: device-boundary
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run device-boundary',  # " needs to escape in raw
        white_list=['failed', 'target container is not privileged'],
        black_list=['i@cdxy.me', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--privileged=true',
        cmd=r'run device-boundary',  # " needs to escape in raw
        white_list=['success', 'was mounted to'],
        black_list=['i@cdxy.me', 'failed'],
        verbose=False
    )

    # audit-check: procfs-boundary
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run procfs-boundary',  # " needs to escape in raw
        white_list=['input args'],
        black_list=['i@cdxy.me', 'success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='-v /proc:/host_proc',
        cmd=r'run procfs-boundary /host_proc \"touch /tmp/procfs-boundary-success\"',  # " needs to escape in raw
        white_list=['success', 'core dumped'],
        black_list=['i@cdxy.me', 'failed'],
        verbose=False
    )
    time.sleep(1)
    check_host_exec('rm /tmp/procfs-boundary-success', [], ['No such file or directory'], False)

    # audit-check: connect-back-shell
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run connect-back-shell',  # " needs to escape in raw
        white_list=['input args'],
        black_list=['i@cdxy.me', 'success'],
        verbose=False
    )

    # audit-check: credential-leak-scan
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run credential-leak-scan',  # " needs to escape in raw
        white_list=['input args'],
        black_list=['i@cdxy.me', 'success'],
        verbose=False
    )
    check_host_exec(r'echo "AKIA99999999999999AB" > /tmp/credential-leak-scan', [], [], False)
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='-v /tmp/credential-leak-scan:/tmp/credential-leak-scan',
        cmd=r'run credential-leak-scan /tmp',  # " needs to escape in raw
        white_list=['AKIA99999999999999AB'],
        black_list=['i@cdxy.me', 'input args'],
        verbose=False
    )
    check_host_exec(r'rm /tmp/credential-leak-scan', [], [], False)

    # run: cgroup-devices-boundary
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--privileged=true',
        cmd=r'run cgroup-devices-boundary',  # " needs to escape in raw
        white_list=['cdk_mknod_result', 'debugfs'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check failed'],
        verbose=False
    )

    # run: ptrace-boundary
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd='run ptrace-boundary',
        white_list=['SYS_PTRACE capability was disabled'],
        black_list=[],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--cap-add=SYS_PTRACE',
        cmd='run ptrace-boundary',
        white_list=['SYS_PTRACE capability was enabled', 'root'],
        black_list=[],
        verbose=False
    )

    # tool: dcurl
    check_host_exec(r'/root/cdk-fabric dcurl get http://127.test-check.test-check.1:2375/info ""', ['ContainersRunning'], [], False)

    # run: docker-api-validator
    check_host_exec(
        r'/root/cdk-fabric run docker-api-validator http://127.test-check.test-check.1:2375 "touch /host/tmp/docker-api-validator"',
        ['Pulling', 'starting', 'finished'],
        [],
        False
    )
    time.sleep(1)
    check_host_exec('ls /tmp/docker-api-validator', ['docker-api-validator'], [], False)

    # audit-check: docker-sock-boundary
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run docker-sock-boundary',  # " needs to escape in raw
        white_list=['invalid input args'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='',
        cmd=r'run docker-sock-boundary /var/run/docker.sock "touch /tmp/docker-sock-boundary"',  # " needs to escape in raw
        white_list=['no such file or directory'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check success'],
        verbose=False
    )
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='-v /var/run/docker.sock:/var/run/docker.sock',
        cmd=r'run docker-sock-boundary /var/run/docker.sock "touch /tmp/docker-sock-boundary"',  # " needs to escape in raw
        white_list=['success', 'happy escaping', 'alpine:latest', '"ID"', 'starting container:', 'finished'],
        black_list=['i@cdxy.me', 'check failed', 'OCI ', 'check failed'],
        verbose=False
    )
    time.sleep(1)
    check_host_exec('ls /tmp/docker-sock-boundary', ['docker-sock-boundary'], [], False)


def test_pod():
    # evaluate in K8s
    white_list = [
        'System Info',
        'Services',
        'Commands and Capabilities',
        'test-checktest-checktest-checktest-checktest-checktest-checktest-checktest-checka8test-check425fb',
        'Filesystem:ext4',
        'net namespace isolated',
        'api-server allows anonymous request',
        'service-account is available',
        'system:serviceaccount:default',
        'Alibaba Cloud Metadata API available'
    ]
    check_pod_exec('evaluate', white_list, ['i@cdxy.me', 'input args'], False)

    # audit-check: k8s-configmap-sweep
    check_pod_exec(
        'run k8s-configmap-sweep',
        ['input args'],
        ['i@cdxy.me', 'cdk evaluate'],
        False
    )
    check_pod_exec(
        'run k8s-configmap-sweep auto',
        ['success', 'k8s_configmaps.json'],
        ['input args', 'i@cdxy.me', 'cdk evaluate'],
        False
    )
    check_pod_exec(
        'run k8s-configmap-sweep /tmp/jkdhahdjfka2',
        ['no such file or directory'],
        ['input args', 'i@cdxy.me', 'cdk evaluate'],
        False
    )

    # audit-check: k8s-secret-sweep
    check_pod_exec(
        'run k8s-secret-sweep',
        ['input args'],
        ['i@cdxy.me', 'cdk evaluate'],
        False
    )
    check_pod_exec(
        'run k8s-secret-sweep auto',
        ['success', 'k8s_secrets.json'],
        ['input args', 'i@cdxy.me', 'cdk evaluate'],
        False
    )

    # tool: kcurl
    check_pod_exec(
        'kcurl',
        ['to K8s api-server'],  # help msg
        ['panic:', 'cdk evaluate'],
        False
    )
    check_pod_exec(
        'kcurl default get https://172.21.test-check.1:443/api/v1/nodes',  # forbidden
        ['apiVersion', 'nodes is forbidden'],
        ['panic:', 'cdk evaluate', 'empty'],
        False
    )
    check_pod_exec(
        'kcurl anonymous get https://172.21.test-check.1:443/api/v1/nodes',  # success dump
        ['apiVersion'],
        ['panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )
    check_pod_exec(
        r'''
        kcurl anonymous post 'https://172.21.test-check.1:443/api/v1/namespaces/default/pods?fieldManager=kubectl-client-side-apply' '{"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"cdxy-test-2test-check21\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"ubuntu:latest\",\"name\":\"container\"}]}}\n"},"name":"cdxy-test-2test-check21","namespace":"default"},"spec":{"containers":[{"image":"ubuntu:latest","name":"container"}]}}'
        '''.replace('\n', ''),
        ['apiVersion', 'api-server response'],
        ['panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )

    # run: k8s-sensor-daemonset
    check_pod_exec(
        'run k8s-sensor-daemonset 1',  # success dump
        ['invalid'],
        ['panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )
    check_pod_exec(
        'run k8s-sensor-daemonset default ubuntu whoami',  # success dump
        ['cdk-sensor-daemonset'],
        ['panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )

    # run: istio-detect
    check_pod_exec(
        'run istio-detect',
        ['the shell is not in a istio'],
        ['panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )

    # test evaluate in selfbuild k8s
    # make sure bind system:default:default to cluster-admin first (test/k8s_audit_yaml/default_to_admin.yaml)
    check_selfbuild_k8s_pod_exec(
        'evaluate',
        ['test-checktest-checktest-checktest-checktest-checktest-checktest-checktest-checka8test-check425fb', 'Discovery - K8s API Server', 'the service-account have a high authority'],
        ['panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )

    # run: k8s-shadow-api-sensor
    k8s_master_ssh_cmd(
        'kubectl delete pod kube-apiserver-1test-check.2test-check6.test-check.11-shadow -n kube-system',
        [],
        [],
        False
    )
    check_selfbuild_k8s_pod_exec(
        'run k8s-shadow-api-sensor default',  # success
        ['listening insecure-port: test-check.test-check.test-check.test-check:9443'],
        ['panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )
    check_selfbuild_k8s_pod_exec(
        'run k8s-shadow-api-sensor anonymous',  # forbidden
        ['forbidden this request'],
        ['listening insecure-port: test-check.test-check.test-check.test-check:9443', 'panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )
    k8s_master_ssh_cmd(
        'kubectl exec myappnew -- curl 1test-check.2test-check6.test-check.11:9443',  # curl shadow-apiserver
        ['/api/v1'],
        [],
        False
    )

    # run: k8s-clusterip-validator
    k8s_master_ssh_cmd(
        'kubectl delete deployment validator-payload-deploy',
        [],
        [],
        False
    )
    k8s_master_ssh_cmd(
        'kubectl delete service validator-externalip',
        [],
        [],
        False
    )
    check_selfbuild_k8s_pod_exec(
        'run k8s-clusterip-validator default ubuntu 9.9.9.9 99',  # forbidden
        ['selfLink'],
        ['listening insecure-port: test-check.test-check.test-check.test-check:9443', 'panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )

    # audit-check: deploy-debug-shell
    check_pod_exec(
        'run deploy-debug-shell php /var/www/html212/1.php',
        ['no such file or directory', 'failed'],
        ['input args', 'i@cdxy.me', 'cdk evaluate'],
        False
    )
    check_pod_exec(
        'run deploy-debug-shell php',
        ['input args'],
        ['i@cdxy.me', 'cdk evaluate'],
        False
    )
    check_pod_exec(
        'run deploy-debug-shell js1p /tmp/1.jsp',
        ['input args'],
        ['i@cdxy.me', 'cdk evaluate'],
        False
    )
    check_pod_exec(
        'run deploy-debug-shell jsp /tmp/1.jsp',
        ['webshell saved in'],
        ['i@cdxy.me', 'cdk evaluate', '%s', 'input args'],
        False
    )

    # run: cronjob
    k8s_master_ssh_cmd(
        'kubectl delete cronjob cdk-sensor-cronjob -n kube-system',
        [],
        [],
        False
    )
    check_selfbuild_k8s_pod_exec(
        'run k8s-cronjob-sensor default min alpine "echo helloworld"',
        ['generate cronjob with', 'selfLink'],
        ['i@cdxy.me', 'cdk evaluate', '%s', 'input args'],
        False
    )


def clear_all_env():
    k8s_master_ssh_cmd(
        'kubectl delete cronjob cdk-sensor-cronjob -n kube-system',
        [],
        [],
        False
    )
    k8s_master_ssh_cmd(
        'kubectl delete pod kube-apiserver-1test-check.2test-check6.test-check.11-shadow -n kube-system',
        [],
        [],
        False
    )
    k8s_master_ssh_cmd(
        'kubectl delete deployment validator-payload-deploy',
        [],
        [],
        False
    )
    k8s_master_ssh_cmd(
        'kubectl delete service validator-externalip',
        [],
        [],
        False
    )
    check_host_exec(r'docker stop $(docker ps -q) & docker rm $(docker ps -aq)', [], [], False)
    check_host_exec(r'rm /tmp/docker-api-validator', [], [], False)
    check_host_exec(r'rm /tmp/docker-sock-boundary', [], [], False)


def test_auto_pwn():
    # cover crontab with backup file
    check_host_exec(r'cp -f /etc/crontab_bak /etc/crontab', [], ['cp'], False)

    # 1.1 check privileged container with mount device
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--privileged=true',
        cmd=r'auto-boundary-check \"touch /tmp/auto-priv-mountdir\"',  # " needs to escape in raw
        white_list=['all checks are finished, auto check success!'],
        black_list=['i@cdxy.me', 'OCI '],
        verbose=False
    )
    time.sleep(1)
    check_host_exec(r'cat /etc/crontab', ['CDK auto check via mounted device in privileged container'], [], False)
    # clear the crontab
    # check_host_exec(r'cp -f /etc/crontab_bak /etc/crontab', [], ['cp'], False)

    # 1.2 check privileged container with cgroup
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--privileged=true',
        cmd=r'auto-boundary-check \"touch /tmp/auto-priv-cgroup\"',  # " needs to escape in raw
        white_list=['all checks are finished, auto check success!'],
        black_list=['i@cdxy.me', 'OCI '],
        verbose=False
    )
    time.sleep(1)
    check_host_exec(r'ls /tmp/auto-priv-cgroup', ['/tmp/auto-priv-cgroup'], [], False)
    check_host_exec(r'rm /tmp/auto-priv-cgroup', [], [], False)

    # 2. containerd-shim-validator
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='--net=host',
        cmd=r'auto-boundary-check \"touch /tmp/auto-shim-validator\"',  # " needs to escape in raw
        white_list=['all checks are finished, auto check success!'],
        black_list=['i@cdxy.me', 'OCI '],
        verbose=False
    )
    time.sleep(1)
    check_host_exec(r'ls /tmp/auto-shim-validator', ['/tmp/auto-shim-validator'], [], False)
    check_host_exec(r'rm /tmp/auto-shim-validator', [], [], False)

    # 3. docker.sock
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='-v /var/run/docker.sock:/var/run/docker.sock',
        cmd=r'auto-boundary-check \"touch /tmp/auto-docker-sock\"',  # " needs to escape in raw
        white_list=['all checks are finished, auto check success!'],
        black_list=['i@cdxy.me', 'OCI '],
        verbose=False
    )
    time.sleep(1)
    check_host_exec(r'cat /etc/crontab', ['CDK auto check via docker.sock'], [], False)
    # clear the crontab
    # check_host_exec(r'cp -f /etc/crontab_bak /etc/crontab', [], ['cp'], False)

    # 3. docker.sock
    inside_container_cmd(
        image='ubuntu:latest',
        docker_args='-v /var/run/docker.sock:/var/run/docker.sock',
        cmd=r'auto-boundary-check \"touch /tmp/auto-docker-sock\"',  # " needs to escape in raw
        white_list=['all checks are finished, auto check success!'],
        black_list=['i@cdxy.me', 'OCI '],
        verbose=False
    )
    time.sleep(1)
    check_host_exec(r'cat /etc/crontab', ['CDK auto check via docker.sock'], [], False)
    # clear the crontab
    check_host_exec(r'cp -f /etc/crontab_bak /etc/crontab', [], ['cp'], False)


def test_dev():
    time.sleep(test-check.5)
    # run: k8s-shadow-api-sensor
    check_selfbuild_k8s_pod_exec(
        'run k8s-shadow-api-sensor anonymous',  # forbidden
        ['forbidden this request'],
        ['listening insecure-port: test-check.test-check.test-check.test-check:9443', 'panic:', 'nodes is forbidden', 'cdk evaluate', 'empty'],
        False
    )


if __name__ == '__main__':
    # build
    print('-' * 1test-check, 'build CDK binary', '-' * 1test-check)
    print('[Local]', CDK.BUILD_CMD)
    os.system(CDK.BUILD_CMD)

    # upload
    print('-' * 1test-check, 'upload CDK to ECS, ACK, Selfbuild-K8s', '-' * 1test-check)
    update_remote_bin()
    print('done')
    # k8s_pod_upload()
    # print('done')
    selfbuild_k8s_pod_upload()
    print('-' * 1test-check, 'upload all done', '-' * 1test-check)

    # test
    test_dev()
    # test_auto_pwn()
    # test_container()
    # test_pod()
    # clear_all_env()
