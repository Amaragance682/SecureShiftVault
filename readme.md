`Use case:

A contractor stores confidential shift data on a tablet/laptop at a worksite. If the device is ever lost the shift history and relevant data must remain confidential and secure.


Features:
-register/login employee (with a hased PIN in SQLite)
-clock-in/clock-out creates and updates a shift entrty in the database
-list shifts decrypts all shifts and shows them

Threat model:
-attacker would steal the DB file (encrypted and offline)
-attacker would use a brute force attack on the offline pin system




How to run assignment 4:
python -m src.app init-db --db vault.db
python -m src.app register alice --db vault.db
python -m src.app login alice --db vault.db
python -m src.app clockin alice --task "Electrician" --location "Reykjavik" --notes "Installed lights" --db vault.db
python -m src.app list alice --db vault.db
python -m src.app clockout alice --notes "Finished up" --db vault.db
python -m src.app list alice --db vault.db
python -m src.app bench --db vault.db
python -m src.app attack alice --mode decrypt --digits 4 --db vault.db`



how to run assignment 5:
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 30 -nodes -subj "/CN=localhost"