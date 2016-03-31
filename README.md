# zbxnetutils
Extension to improve the monitoring of network appliance with zabbix
## How it works
Da tradurre:
Zabbix, pur migliorando molto la low level discovery nella versione 3, non ha ancora la possibilità di gestire una logica sui dati in ingresso o di confrontare più item per generarne uno calcolato sulla base di funzioni più complesse di un calculated item.
L'idea alla base del software è creare un microservice http che accetti chiamate in get con parametri e ritorni un json compatibile con LLD se usato per discovery o richiami zabbix_sender per inviare i dati.
Ho preferito un servizio http sempre in esecuzione piuttosto che richiamare uno script via external check per evitare continue chiamate all'interprete python e sfruttare le caratteristiche async del framework Tornado.

## Funzioni attualmente sopportate:
#### LLD discovery di interfacce tipo trunk (static o LACP)
Non tutti gli switch ritornano come ifType diverso le interfacce aggregate, devo confrontare il bridgeindex con l'iftype togliendo le interfacce ethernet (iftype=6)
#### Elenco di interfacce tagged e untagged per VLAN
E' necessario fare un calcolo su una bitmask delle interfacce associate o meno a una vlan. Invio a zabbix via zabbixsender i nomi (ifName) delle interfacce associate ad ogni vlan, via discovery nativa di zabbix creo gli item tipo trapper.
Il service http può essere usato sia come item di zabbix sia come query diretta che ritorna un json, eventualmente da utilizzare per applicazioni esterne.
