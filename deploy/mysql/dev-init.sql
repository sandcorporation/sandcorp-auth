-- Local only (docker-compose.yml, docker-compose.prod-local.yml): let the app user create the
-- pytest database (test_sandcorp_auth). Production accounts are made by the coordinator on HeatWave.
GRANT ALL PRIVILEGES ON `test\_sandcorp\_auth%`.* TO 'sandcorp_auth'@'%';
