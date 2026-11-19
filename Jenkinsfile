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
                    sh 'docker run --rm -v $(pwd):/app python:3.11-slim sh -c "pip install -q bandit && bandit -r /app/app.py /app/init_db.py"'
                }
            }
        }

        stage('3. Despliegue (Deploy)') {
            steps {
                echo 'Desplegando contenedor en la red interna de Docker...'
                sh '''
                    docker rm -f ${APP_NAME} || true
                    docker run -d --name ${APP_NAME} --network ${NETWORK_NAME} -p 5000:5000 ${APP_NAME}:latest
                '''
            }
        }
    }
}
