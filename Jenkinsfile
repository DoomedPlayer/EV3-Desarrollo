pipeline {
    agent any

    environment {
        APP_NAME = "securedev-app"
        NETWORK_NAME = "devsecops-net"
    }

    stages {
        stage('1. Construcción (Build)') {
            steps {
                echo 'Construyendo imagen Docker de la aplicación...'
                sh 'docker build -t ${APP_NAME}:latest .'
            }
        }

        stage('2. Pruebas de Seguridad SAST (Test)') {
            steps {
                echo 'Ejecutando análisis estático de seguridad con Bandit...'
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh 'docker run --rm ${APP_NAME}:latest sh -c "pip install -q bandit && bandit -r /app/app.py /app/init_db.py"'
                }
            }
        }

        stage('2.1. Auditoría de Dependencias (SCA)') {
            steps {
                echo 'Analizando vulnerabilidades en dependencias de terceros con pip-audit...'
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh 'docker run --rm ${APP_NAME}:latest sh -c "pip install -q pip-audit && pip-audit -r /app/requirements.txt"'
                }
            }
        }

        stage('3. Despliegue (Deploy)') {
            steps {
                echo 'Desplegando contenedor en la red interna de Docker...'
                sh '''
                    docker rm -f ${APP_NAME} || true
                    docker run -d --name ${APP_NAME} --network ${NETWORK_NAME} -p 5000:5000 ${APP_NAME}:latest
                    sleep 3
                '''
            }
        }

        stage('4. Pruebas DAST (OWASP ZAP)') {
            steps {
                echo 'Ejecutando escaneo dinámico de seguridad con OWASP ZAP...'
                sh '''
                    docker volume create zap-reports || true
                    docker run --rm -u root -v zap-reports:/zap/wrk ghcr.io/zaproxy/zaproxy:stable chown -R 1000:1000 /zap/wrk
                '''
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    shsh 'docker run --rm --network ${NETWORK_NAME} -v zap-reports:/zap/wrk ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -I -t http://${APP_NAME}:5000 -r reporte_zap.html'
                }
                sh 'docker run --rm -v zap-reports:/zap/wrk ${APP_NAME}:latest cat /zap/wrk/reporte_zap.html > reporte_zap.html || true'
                archiveArtifacts artifacts: 'reporte_zap.html', allowEmptyArchive: true
            }
        }
    }
}