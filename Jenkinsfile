def checkout() {
    step([$class: 'WsCleanup'])
    checkout([
        $class: 'GitSCM',
        branches: [[name: '*/${BRANCH}']],
        extensions: [[$class: 'RelativeTargetDirectory', relativeTargetDir: 'core']], 
        userRemoteConfigs: [[credentialsId: 'jenkins', url: 'git@bitbucket.org:openvpntechnologies/ovpn3-core.git']]
    ])
}

def build_linux() {
    checkout() 
    withEnv(["O3=$WORKSPACE"]) {
        dir("$O3/core/test/ovpncli") {
            sh 'ECHO=1 PROF=linux ASIO_DIR=~/asio MTLS_SYS=1 LZ4_SYS=1 NOSSL=1 OUTBIN=cli_mbed $O3/core/scripts/build cli'
            sh 'ECHO=1 PROF=linux ASIO_DIR=~/asio OPENSSL_SYS=1 LZ4_SYS=1 OUTBIN=cli_ssl $O3/core/scripts/build cli'
        }
    }
    archiveArtifacts 'core/test/ovpncli/cli_mbed,core/test/ovpncli/cli_ssl'
}

def build_windows() {
    checkout()
    dir('core\\win') {
        bat 'copy c:\\Jenkins\\parms_local.py'        
        bat 'python buildep.py'
        bat 'python build.py'
    }
    archiveArtifacts 'core/win/cli.exe,core/win/cli.obj'
}

stage('Build') {
    parallel(
        linux: {
            node('linux_slave') {
                build_linux()          
            }
        },
        windows: {
            node('windows_slave') {
                build_windows()
            }
        }
    )    
}
