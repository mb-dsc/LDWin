LDWIN
=====
Een port van de originele LDWin.au3 naar Powershell. ([LDWin van Chris Hall op Github](https://github.com/chall32/LDWin))

Diverse aanpassingen en verbeteringen in het parsen van de data en de opzet van de GUI.


<img width="746" height="527" alt="image" src="assets/ldwin-screenshot.png" />


### Wat doet het
Link Discovery is een process om informatie van een direct connected netwerk device af te kunnen halen, zoals bijvoorbeeld switches.
Het kan je ondersteunen met het troubleshooten van connectie problemen.

LDWin supports de volgende methodes van discovery:

- [CDP](http://en.wikipedia.org/wiki/Cisco_Discovery_Protocol) - Cisco Discovery Protocol
- [LLDP](http://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol) - Link Layer Discovery Protocol

### Hoe te gebruiken
Je dient administratieve rechten te hebben om dit te kunnen uitvoeren.

1. Open een PowerShell terminal in privileged mode
2. Start het script LDWin.ps1
3. Kies in de dropdown box "Network Connection:" de netwerk adapter waarvan de informatie wilt opvragen
4. Click "Get Link Data"
5. LDWin zal dan op de geselecteerde network adapter gaan luisteren naar link protocol aankondigingen. Dit kan tot 60 seconden duren.
6. Als er een aankondiging is ontvangen, wordt de informatie in de Results sectie getoond.
7. Gebruik de "Save Link Data" knop om deze data in een text file te bewaren.

NOTE: Je hebt geen valide TCP/IP adres nodig om valide link data te ontvangen.
