from feature1 import *
from feature2 import *
from feature3 import *

#Parametro di sicurezza
N=64

### Generazione di chiavi e certificati
print("- Cleaning folders\n")
shell("rm -f -r client server MS CA common player*")

print("- Killing all openssl processes\n")
shell("killall -s SIGKILL openssl")

print("- Creating folders\n")
shell("mkdir server MS CA common")

print("- Generating ecparams\n")
shell("openssl ecparam -name prime256v1 -out common/prime256v1.pem") # Genera i parametri per la curva ellittica prime256v1
shell("openssl ecparam -in prime.pem -text")

print("- Generating ECDSA private and public keys\n") 
shell("openssl genpkey -paramfile common/prime256v1.pem -out server/ecdsa_key.pem") # Genera la chiave privata per il server
shell("openssl pkey -in server/ecdsa_key.pem -pubout -out common/serverkey.pem") # Genera la chiave pubblica per il server
shell("openssl genpkey -paramfile common/prime256v1.pem -out CA/ecdsa_key.pem") # Genera la chiave privata per la CA
shell("openssl pkey -in CA/ecdsa_key.pem -pubout -out common/cakey.pem") # Genera la chiave pubblica per la CA
shell("openssl genpkey -paramfile common/prime256v1.pem -out MS/ecdsa_key.pem") # Genera la chiave privata per il MS
shell("openssl pkey -in MS/ecdsa_key.pem -pubout -out common/mskey.pem") # Genera la chiave pubblica per il MS

print("- Generating dsaparams\n")

# Il file dsaparam.pem è l’unico file che non viene generato ad ogni esecuzione del codice.
# Tale file contiene i parametri necessari per la generazione delle chiavi DSA, 
# utilizzate per il commitment di Pedersen, con taglia di p pari a 2048 bit e taglia di q di 256 bit. 
# tale file è già presente all’interno del progetto perché per generarlo è stata utilizzata la versione 3.2.0 di OpenSSL. 
# Tale versione, infatti, permette di specificare il numero di bit del primo q oltre al numero di bit del primo p

#shell("openssl dsaparam -out common/dsaparam.pem 1024")
shell("cp ./dsaparam.pem ./common/dsaparam.pem") # Comando che doveva essere eseguito una sola volta
shell("openssl dsaparam -in common/dsaparam.pem -text") # Mostra i parametri del file dsaparam.pem

print("- Generating auto signed certification of root certification authority\n")
# Per fare la Certification Authority (CA) abbiamo usato una configurazione custom e non -config openssl.cnf
shell("openssl req -x509 -key CA/ecdsa_key.pem -days 3650 -out common/CAcert.pem -subj \"/C=US/ST=AZ/L=Tempe/O=SW/CN=ca.demo\"")
# Mostra a video il certificato della CA
shell("openssl x509 -in CA/CAcert.pem -text") 
print("- Generating tree directory of root certification authority\n")
shell("mkdir CA/demoCA") # Directory che contiene la configuazione della CA
shell("cp common/CAcert.pem CA/demoCA/cacert.pem") # Metto una copia della configurazione creata prima della CA nella directory della CA
shell("touch CA/demoCA/index.txt") # Inizializzo il database dei certificati emessi dalla CA
shell("touch CA/demoCA/serial") # Inizializzo il database dei certificati emessi dalla CA
shell("echo \"00\" >> CA/demoCA/serial") # Inizializzo il contatore dei certificati emessi dalla CA
shell("mkdir CA/demoCA/private") # Directory con la chiave privata della CA
shell("cp CA/ecdsa_key.pem CA/demoCA/private/cakey.pem") # Copio la chiave privata della CA nella directory della CA
shell("mkdir CA/demoCA/newcerts") # Directory con i certificati emessi dalla CA

print("- Generating certificate request of MS\n")
# RICHIESTE DI CERTIFICATO DIGITALE ALLA CA. 

# RICHIESTA DI CERTIFICATO DIGITALE DEL MS.
shell("openssl req -new -key MS/ecdsa_key.pem -out MS/requestMS.pem -subj \"/C=US/ST=AZ/L=Tempe/O=SW/CN=MS.demo\"") # Genera la RICHIESTA di un certificato digitale per il MS
print("- Root certification authority sign certificate request of MS\n")
# ORA BISOGNA GENERARE IL VERO E PROPRIO CERTIFICATO DIGITALE PER IL MS.
shell("cd CA; yes | openssl ca -in ../MS/requestMS.pem -out ../common/MScert.pem -policy policy_anything") # Rilascia un certificato digitale per il MS (- policy policy_anything: ignora le policy definite sui dati. In questo modo la CA non controlla i dati inseriti nel certificato)

print("- Generating certificate request of Server\n")
# RICHIESTA DI CERTIFICATO DIGITALE ALLA CA DEL SERVER
shell("openssl req -new -key server/ecdsa_key.pem -out server/requestS.pem -subj \"/C=IT/ST=CAM/L=ROME/O=MR_JOKER/CN=SERVER\"")
#shell("openssl x509 -in CA/CAcrt.pem -text")
print("- Root certification authority sign certificate request of Server\n")
shell("cd CA; yes | openssl ca -in ../server/requestS.pem -out ../common/Scert.pem -policy policy_anything")

# Generazione delle chiavi dsa per i player. Le chiavi ecdsa vengono generate all'occorrenza in feature3_phase1_T1
numero_di_player=3
players_CF = ['AAAAAAAAAAAAAAAA', 'BBBBBBBBBBBBBBBB', 'CCCCCCCCCCCCCCCC']
players_pedersen_keys = []
players_GP = []
players_LD = []
players_R = []
players_L = []
generate_context(numero_di_player)
SK_S = load_ecdsa_secret("server")
PK_S = load_ecdsa_public("serverkey")

### GENERAZIONE GREEN PASS
print("\n\nFEATURE 2: GENERAZIONE GREEN PASS\n\n")

generate_fake_ms_db()
generate_fake_ms_revoked_gp_db()

L = ["first_name","last_name","CF","birth","vaccine","UID"]
  
for i in range(numero_di_player):
  SK_pedersen,PK_pedersen = client_feature2_phase1_t0(i)
  players_pedersen_keys.append((SK_pedersen,PK_pedersen))
  (GP,LD,R) = server_feature2_phase1_t0(i,PK_pedersen,players_CF[i])

  players_GP.append(GP)
  players_LD.append(LD)
  players_R.append(R)
  
  if(verify_gp(GP) == True):
    print("[Player ", i, "]: ha ricevuto un Green Pass valido")
  else:
    print("[Player ", i, "]: NON ha ricevuto un Green Pass valido")
    exit()
  
## SE SI VUOLE REVOCARE IL GREEN PASS DI UN PLAYER
#update_fake_ms_revoked_gp_db(UID="foocommit",GP=GP)

### REGISTRAZIONE
print("\n\nFEATURE 3: REGISTRAZIONE\n\n")

generate_fake_server_db()

for i in range(numero_di_player):
  username = "Player"+str(i)
  res = server_feature3_phase1_t0(GP,username)
  if res == True:
    print("[Player ", i, "]: può registrarsi al Server")
  else:
    print("[Player ", i, "]: NON può registrarsi al Server")
    continue

  res = client_server_feature3_phase1_t1(players_pedersen_keys[i][0])
  if res == True:
    print("[Player ", i, "]: ha dimostrato (tramite ZKP) che possiede la SK del Green Pass mostrato al Server")
  else:
    print("[Player ", i, "]: NON possiede la SK")
    exit()

  print("[Player ", i, "]: sta dimostrando che è in grado di aprire il commitment")
  res = client_server_feature3_phase1_t2(players_pedersen_keys[i][0],players_GP[i],players_R[i],players_LD[i],["UID"])
  if res == True:
    print("[Player ", i, "]: ha dimostrato (tramite ZKP) che conosce tutte le informazioni per aprire il commitment")
  else:
    print("[Player ", i, "]: NON non possiede le informazioni per aprire il commitment")
    exit()
  
  server_feature3_phase1_t3(username,GP,N)
    
  print("[Player ", i, "]: è stato registrato.")


### LOGIN
print("\n\nFEATURE 3: LOGIN\n\n")

for i in range(numero_di_player):
  username = "Player"+str(i)
  res = server_feature3_phase2_t0(GP,username)
  if res == True:
    print("[Player ", i, "]: può loggarsi al Server")
  else:
    print("[Player ", i, "]: NON possiede la SK")
    exit()


  res = client_server_feature3_phase2_t1(players_pedersen_keys[i][0])
  if res == True:
    print("[Player ", i, "]: ha dimostrato (tramite ZKP) che possiede la SK del Green Pass mostrato al Server")
  else:
    print("[Player ", i, "]: NON possiede la SK")
    exit()

  print("[Player ", i, "]: sta dimostrando che è in grado di aprire il commitment")
  res = client_server_feature3_phase2_t2(players_pedersen_keys[i][0],players_GP[i],players_R[i],players_LD[i],["UID"])
  if res == True:
    print("[Player ", i, "]: ha dimostrato (tramite ZKP) che conosce tutte le informazioni per aprire il commitment")
  else:
    print("[Player ", i, "]: NON non possiede le informazioni per aprire il commitment")
    exit()

  res= server_feature3_phase2_t3(username,GP,N)
  if res == True:
    print("[Player ", i, "]: era stato correttamente registrato in passato.")
  else:
    print("[Player ", i, "]: NON era stato correttamente registrato in passato.")
    exit()
    
  print("[Player ", i, "]: è correttamente loggato alla sito.")  


### ACCESSO ALLA SALA VIRTUALE
print("\n\nFEATURE 2: ACCESSO ALLA SALA VIRTUALE\n\n")

for i in range(numero_di_player):
  L = server_feature2_phase2_t1(L)
  players_L.append(L)
  (GP,D_requested) = client_feature2_phase2_t2(GP,L,LD)
  if server_feature2_phase2_t2(GP,D_requested) == True:
    print("[Player ", i, "]: ha un Green Pass valido per accedere alla sala virtuale. Il server ora procede con ulteriori controlli")
  else:
    print("[Player ", i, "]: NON ha un Green Pass valido per accedere alla sala virtuale")
    exit()

  res = client_server_feature2_phase2_t3(SK_pedersen)
  if res == True:
    print("[Player ", i, "]: ha dimostrato (tramite ZKP) che possiede la SK del Green Pass mostrato al Server")
  else:
    print("[Player ", i, "]: NON possiede la SK")
    exit()

  print("[Player ", i, "]: sta dimostrando che è in grado di aprire il commitment")
  res = client_server_feature2_phase2_t4(SK_pedersen,GP,R,LD,L)
  if res == True:
    print("[Player ", i, "]: ha dimostrato (tramite ZKP) che conosce tutte le informazioni per aprire il commitment")
  else:
    print("[Player ", i, "]: NON non possiede le informazioni per aprire il commitment")
    exit()
  print("[Player ", i, "]: è ammesso alla partita.")


### GENERAZIONE DI NUMERI CASUALI
print("\n\nFEATURE 1: GENERAZIONE DI NUMERI CASUALI\n\n")


print("[Server]: ha generato correttamente la sua coppia (PK,SK) temporanea per questa partita")

### Feature 1 fase 1
# Client T1:
for i in range(numero_di_player):
    PK_i,SK_i= client_feature1_phase1_T1(i)
    print("[Player", i, "]: ha generato correttamente la sua coppia (PK,SK) temporanea per questa partita")
    K_P.update({PK_i : SK_i})

# Server T1:
k=list(K_P.keys())

for i in range(numero_di_player):
    server_feature1_phase1_T1(k[i])
print("[Server]: ha creato correttamente G")

# Client T2:
for i in range(numero_di_player):
    sigma_player_i.append(client_feature1_phase1_T2(k[i],K_P[k[i]]))
    print("[Player", i, "]: è presente in G ed ha generato correttamente la firma sigma_", i)

# Server T2:
for i in range(numero_di_player):
    server_feature1_phase1_T2(sigma_player_i[i])
print("[Server]: generato Sigma ed ha verificato correttamente le firme dei player")

# Client T3:
for i in range(numero_di_player):
    client_feature1_phase1_T3()
    print("[Player", i, "]: ha verificato correttamente tutte le firme in Sigma")        


### Feature 1 fase 2
# Client T1:
for i in range(numero_di_player):
    c,r=client_feature1_phase2_T1(N)
    commit_feature1_rand_player_i.append(c)
    rand_player_i.append(r)
    print("[Player", i, "]: ha generato correttamente la propria randomness e il commit")

# Server T1:
for i in range(numero_di_player):
    server_feature1_phase2_T1_aggregate_commit(commit_feature1_rand_player_i[i])
sigma_c_p,rand_server= server_feature1_phase2_T1(N, SK_S)
print("[Server]: ha generato correttamente la propria randomness e il commit, ha aggregato tutti i commit dei player in C, ed ha generato la firma sigma_c_p")

# Client T2:
for i in range(numero_di_player):
    sigma_r_C_player_i.append(client_feature1_phase2_T2( commit_feature1_rand_player_i[i], PK_S, sigma_c_p,K_P[k[i]],rand_player_i[i]))
    print("[Player", i, "]: è presente in C, ha verificato la firma sigma_c_p, ha generato correttamente la propria firma sigma_r_C")

# Server T2:
for i in range(numero_di_player):
    server_feature1_phase2_T2_aggregate_randomness_sigma(rand_player_i[i], sigma_r_C_player_i[i])
print("[Server]: ha aggregato tutte le firme sigma_r_C dei player e le relative randomness")

server_feature1_phase2_T2(rand_server)
print("[Server]: ha verificato correttamente che le randomness inviate dai player sono quelle sotto i commitment")

sigma_final,R_S =server_feature1_phase2_T3(SK_S)
print("[Server]: ha generato correttamente la firma sigma_final e la randomness R_S")

for i in range(numero_di_player):
    R_P_i.append(client_feature1_phase2_T3(PK_S, sigma_final))
    print("[Player", i, "]: ha verificato correttamente la firma sigma_final, ha verificato che i commit ricevuti nascondono esattamente le randomness ricevute, ha verificato che tutte le firme dei player nella partita sono valide ed ha calcolato correttamente la stringa estratta R_P_i")

print("\nRandomness calcolata dal server:", R_S)

for i in range(numero_di_player):
    print("Randomness calcolata dal player", i,":", R_P_i[i])
    if(R_P_i[i] != R_S):
        print("player", i ,"non in accordo: PARTITA NON VALIDA")
print("TUTTI CONTRIBUTI COERENTI: PARTITA VALIDA")

#delete_context(numero_di_player)