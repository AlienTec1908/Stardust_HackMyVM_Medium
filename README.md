# Stardust - HackMyVM (Medium)
 
![Stardust.png](Stardust.png)

## Übersicht

*   **VM:** Stardust
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Stardust)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 21. Juli 2023
*   **Original-Writeup:** https://alientec1908.github.io/Stardust_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "Stardust"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration einer GLPI-Installation auf Port 80, bei der Standard-Credentials (`tech:tech`) zum Login führten. Innerhalb von GLPI wurde ein Hinweis auf einen VHost `intranetik.stardust.hmv` gefunden. Dieser VHost hatte eine Upload-Funktion, deren Filter durch das Hochladen einer `.htaccess`-Datei umgangen wurde. Dies ermöglichte die Ausführung einer PHP-Webshell (mit `.ben`-Endung) und somit Remote Code Execution (RCE) als `www-data`. Als `www-data` wurden GLPI-Datenbank-Credentials ausgelesen, die Zugriff auf MariaDB erlaubten. Dort wurde eine weitere Datenbank (`intranetikDB`) mit einem Benutzer `tally` und dessen Passwort-Hash gefunden. Nach dem Knacken des Hashes (`tally:bonita`) konnte zu diesem Benutzer gewechselt werden. Die User-Flag wurde als `tally` gefunden. Die Privilegieneskalation zu Root erfolgte durch die Manipulation einer Konfigurationsdatei (`/opt/config.json`), die von einem als Root laufenden Cronjob (`/opt/meteo`) gelesen wurde. Dieser Cronjob führte `tar`-Befehle aus, die das `/root`-Verzeichnis in ein für `tally` lesbares Archiv packten.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `wfuzz`
*   `curl`
*   `Burp Suite`
*   `nc` (netcat)
*   `python3`
*   `mysql` (bzw. `mariadb-client`)
*   `john` (John the Ripper)
*   `su`
*   `sudo`
*   `find`
*   `ls`
*   `cat`
*   `wget`
*   `pspy64`
*   `file`
*   `jq`
*   `tar`
*   `nano`
*   `cp`
*   `mv`
*   `cd`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Stardust" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mit `arp-scan` (`192.168.2.111`).
    *   Eintrag von `stardust.hmv` in lokale `/etc/hosts`.
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Apache 2.4.56 mit GLPI).

2.  **Web Enumeration (GLPI & VHost Entdeckung):**
    *   `nikto` auf Port 80 fand typische GLPI-Struktur, Directory Indexing für mehrere Verzeichnisse (u.a. `/install/`, `/config/`) und eine `/README.md`.
    *   `gobuster` bestätigte die GLPI-Verzeichnisstruktur und fand `status.php`.
    *   Ein SQLi-Versuch auf der GLPI-Login-Seite war erfolglos.
    *   Login in GLPI mit Standard-Credentials `tech:tech` war erfolgreich.
    *   Innerhalb eines GLPI-Tickets (ID 6) wurde der Hinweis auf einen VHost `intranetik.stardust.hmv` gefunden.

3.  **Initial Access (Webshell Upload via `.htaccess` Bypass auf VHost):**
    *   Der VHost `intranetik.stardust.hmv` zeigte eine Dateiupload-Seite mit Filter für gefährliche Endungen.
    *   Erfolgreicher Upload einer `.htaccess`-Datei (via Burp Suite/`curl`) mit Inhalt `AddType application/x-httpd-php .ben`, um den Apache-Server anzuweisen, `.ben`-Dateien als PHP zu interpretieren.
    *   Erfolgreicher Upload einer PHP-Webshell (`chehade.ben`) mit der neuen Endung.
    *   Ausführung der Webshell (`http://intranetik.stardust.hmv/chehade.ben?cmd=id`) bestätigte RCE als `www-data`.
    *   Erlangung einer Reverse Shell als `www-data` durch Ausführen eines Bash-Reverse-Shell-Payloads über die Webshell.

4.  **Post-Exploitation / Privilege Escalation (von `www-data` zu `tally`):**
    *   Als `www-data` wurde die GLPI-Konfigurationsdatei `/var/www/html/config/config_db.php` gelesen, die die Datenbank-Credentials `glpi:D6jsxBGek` enthielt.
    *   Login in die MariaDB-Datenbank. Entdeckung einer zusätzlichen Datenbank `intranetikDB`.
    *   In `intranetikDB.users` wurde der Benutzer `tally` mit dem bcrypt-Passwort-Hash `$2b$12$zzVJjW1Bvm4WqcPy6nqDFU4JRh2mMpbeKKbP21cn7FKtNy4Ycjl.` gefunden.
    *   Knacken des Hashes für `tally` mit `john` und `rockyou.txt` ergab das Passwort `bonita`.
    *   Wechsel zum Benutzer `tally` mittels `su tally` und dem Passwort `bonita`.

5.  **Privilege Escalation (von `tally` zu `root`):**
    *   Als `tally` wurde die User-Flag `f4c0971d361c2844bb9730846dc330c2` in `/home/tally/user.txt` gelesen.
    *   `sudo -l` für `tally` zeigte keine Sudo-Rechte; SUID-Binaries waren Standard.
    *   Hochladen und Ausführen von `pspy64` als `tally` enthüllte einen als `root` laufenden Cronjob (oder häufig ausgeführten Prozess), der das Skript `/opt/meteo` ausführt.
    *   Das Skript `/opt/meteo` las Koordinaten aus `/opt/config.json` und führte bei Überschreiten eines Schwellenwerts `tar`-Befehle aus, um u.a. `/root` nach `/var/backups/backup.tar` zu sichern.
    *   `tally` hatte Schreibrechte auf `/opt/config.json` und Leserechte auf `/var/backups/backup.tar`.
    *   Manipulation der Koordinaten in `/opt/config.json`, um das Backup auszulösen.
    *   Nachdem der Cronjob das Backup erstellt hatte, wurde `/var/backups/backup.tar` von `tally` kopiert, via Python HTTP-Server auf die Angreifer-Maschine übertragen und dort extrahiert.
    *   Die Root-Flag `052cf26a6e7e33790391c0d869e2e40c` wurde aus dem extrahierten `/root/root.txt` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Standard-Credentials (GLPI):** Verwendung von `tech:tech` ermöglichte initialen Anwendungszugriff.
*   **Informationsleck in Anwendung:** Hinweis auf internen VHost (`intranetik.stardust.hmv`) in einem GLPI-Ticket.
*   **Unsicherer Datei-Upload mit `.htaccess`-Bypass:** Ermöglichte RCE durch Hochladen einer `.htaccess`-Datei zur Änderung der PHP-Handler-Konfiguration und einer anschließenden Webshell.
*   **Klartext-Credentials in Konfigurationsdatei:** Datenbankzugangsdaten in `config_db.php` lesbar für `www-data`.
*   **Passwort-Cracking (bcrypt):** Knacken von Datenbank-Passwort-Hashes.
*   **Unsicherer Cronjob / Privilegierter Prozess:** Ein als Root laufendes Skript (`/opt/meteo`) las eine von einem weniger privilegierten Benutzer beschreibbare Konfigurationsdatei (`/opt/config.json`).
*   **Logikfehler im Backup-Skript:** Das Skript erstellte ein Backup von sensiblen Verzeichnissen (inkl. `/root`) in ein für den angreifenden Benutzer lesbares Archiv, ausgelöst durch manipulierbare Eingaben.
*   **Directory Indexing:** Mehrere Verzeichnisse der GLPI-Installation waren browsebar.

## Flags

*   **User Flag (`/home/tally/user.txt`):** `f4c0971d361c2844bb9730846dc330c2`
*   **Root Flag (`/root/root.txt` gelesen via extrahiertem Tar-Archiv):** `052cf26a6e7e33790391c0d869e2e40c`

## Tags

`HackMyVM`, `Stardust`, `Medium`, `GLPI`, `.htaccess Upload`, `RCE`, `Password Cracking`, `Cronjob Exploitation`, `Tar Exploit`, `Configuration Manipulation`, `Linux`, `Web`, `Privilege Escalation`
