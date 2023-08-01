import math
from common_functions import *

last_UID = 41 

def get_pedersen_key(x,y,p,q,g):
  r = get_random_element_of_Zq(q) # r is an element of Zq
  h = pow(g,r,p)
  return (x,y,p,q,g,h),(y,p,q,g,h)

def generate_fake_ms_db():
  with open('MS/DB.csv', 'w', newline='') as csvfile:
    fieldnames = ['first_name', 'last_name','CF','birth','vaccine','UID', 'PK']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerow({'first_name': 'Baked', 'last_name': 'Beans','CF':'AAAAAAAAAAAAAAAA','birth':'02/04/2001','vaccine':"None",'UID':"", 'PK':""})
    writer.writerow({'first_name': 'Lovely', 'last_name': 'Spam','CF':'BBBBBBBBBBBBBBBB','birth':'11/09/2001','vaccine':'Moderna','UID':41,'PK':""})
    writer.writerow({'first_name': 'Wonderful', 'last_name': 'Spam','CF':'CCCCCCCCCCCCCCCC','birth':'07/01/2015','vaccine':'AstraZeneca','UID':"", 'PK':""})

def generate_fake_ms_revoked_gp_db():
  with open('MS/Revoked_GP_DB.csv', 'w', newline='') as csvfile:
    fieldnames = ['UID','GP_revoked']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    #writer.writerow({'UID': '1', 'GP_revoked': ''})
    
def update_fake_ms_revoked_gp_db(UID,GP):
  with open('MS/Revoked_GP_DB.csv', newline='') as source, open('MS/Revoked_GP_DBtmp.csv', 'w', newline='') as dest:
    reader = csv.DictReader(source)
    writer = csv.DictWriter(dest, fieldnames=reader.fieldnames)
    writer.writeheader()
    for row in reader:
      if(row['UID'] == UID): #If the person is found
        row['GP'] = str(GP) #pickle.dumps(PK_U).decode() #Store PK
      writer.writerow(row)
    writer.writerow({'UID': UID, 'GP_revoked': str(GP)})
  shell("mv MS/Revoked_GP_DBtmp.csv MS/Revoked_GP_DB.csv")
  

def pedersenCommit(g,h,p,d,r):
  """ Converts d in the corresponding element of Zq and computes the Pedersen commitment"""
  #print("[DEBUG] d:",d," -> ")
  #print(int(string2bin(d)))
  m = int(string2bin(d)) # decode stringa in binario
  return str((pow(g,m,p) * pow(h,r,p)) % p)

def generate_gp(id_player,PK_U, C):
  PK_MS = shell("cat common/mskey.pem").decode("utf-8")
  GP = {}
  GP['PK'] = encode_bytes_to_base64(pickle.dumps(PK_U)) #Store PK
  GP.update(C)
  GP['exp_date'] = '01/01/2025'
  GP['PK_MS'] = PK_MS #Store PK of MS
  GP['signature'] = '' #Empty signature
  #with open('MS/tmp.json', 'w') as file:
  #  json.dump(GP, file) 
  #signature = shell("openssl dgst -sign MS/ecdsa_key.pem MS/tmp.json")
  #GP['signature'] = encode_bytes_to_base64(signature)
  #shell("rm MS/tmp.json")
  GP_json = json.dumps(GP) #Stringa da firmare
  #print("[DEBUG] Stringa firmata:\n",GP_json)
  #print("[DEBUG] SK MS:\n",load_ecdsa_secret("MS"))
  signature = hash_and_sign(m=GP_json,SK=load_ecdsa_secret("MS"))
  signature_base64 = encode_bytes_to_base64(signature)
  #print("[DEBUG] Firma:\n",signature_base64)
  GP['signature'] = signature_base64

  with open('player{0}/GP.json'.format(str(id_player)), 'w') as file:
    json.dump(GP, file)
  return GP

  
def client_feature2_phase1_t0(id_player):
  #print("[DEBUG] Generating DSA key for player",id_player)
  SK_dsa = extract_dsa_secret("player{0}/dsa_key.pem".format(str(id_player))) #la chiave è già stata generata
  SK_pedersen,PK_pedersen = get_pedersen_key(*SK_dsa)
  return SK_pedersen,PK_pedersen

def server_feature2_phase1_t0(id_player,PK_U,CF): #CF identifies the person and is known to the server
  (_,p,q,g,h) = PK_U #Extract q from user's PK
  global last_UID
  LD = {} #The dict containing the secret values
  R = {} #The dict containing the random values
  C = {} #The dict containing the commitments
  with open('MS/DB.csv', newline='') as source, open('MS/DBtmp.csv', 'w', newline='') as dest:
    reader = csv.DictReader(source)
    writer = csv.DictWriter(dest, fieldnames=reader.fieldnames)
    writer.writeheader()
    for row in reader:
      if(row['CF'] == CF): #If the person is found
        if(row['UID'] == ''): #Assign UID if not already assigned
          row['UID'] = str(last_UID + 1)
          last_UID = last_UID + 1
        row['PK'] = encode_bytes_to_base64(pickle.dumps(PK_U))#pickle.dumps(PK_U).decode() #Store PK
        for (k,v) in row.items():
          if k == 'PK': continue
          LD[k] = v
          R[k] = get_random_element_of_Zq(q)
          C[k] = pedersenCommit(g=g,p=p,h=h,d=LD[k],r=R[k])
          GP = generate_gp(id_player,PK_U,C)
          #print("[DEBUG] k:",k," v:",v," LD[k]:",LD[k]," R[k]:",R[k]," C[k]:",C[k])
      writer.writerow(row)
  shell("mv MS/DBtmp.csv MS/DB.csv")
  return (GP,LD,R)


def server_feature2_phase2_t1(L):
  return L

def client_feature2_phase2_t2(GP,L,LD):
  """GP: Green Pass del player che sta eseguendo il protocollo """
  D_requested = []
  for l in L:
    D_requested.append(LD[l])
  return GP,D_requested

def server_feature2_phase2_t2(GP,D_requested):
  """GP: Green Pass del player che sta eseguendo il protocollo """
  if(verify_gp(GP) == False):
    return False
  exp_date = GP['exp_date']
  exp_date = datetime.date(day=int(exp_date.split("/")[0]),month=int(exp_date.split("/")[1]),year=int(exp_date.split("/")[2]))
  #print(exp_date)
  if(exp_date < datetime.date.today()):
    return False
  
  with open('MS/Revoked_GP_DB.csv', newline='') as revokedDB:
    reader = csv.DictReader(revokedDB)
    for row in reader:
      if row['UID'] == GP['UID']:
        if row['GP_revoked'] == str(GP):
          return False

  return True



def client_server_feature2_phase2_t3(SK_pedersen):
  """SK: Chiave privata del player che sta eseguendo il protocollo """
  (x,y,p,q,g,h) = SK_pedersen
  return ZKP(x,g,p,q,y)

def client_server_feature2_phase2_t4(SK_pedersen,GP,R,LD, L):
  """SK: Chiave privata del player che sta eseguendo il protocollo """
  (x,y,p,q,g,h) = SK_pedersen
  for l in L:
    c = GP[l]
    r = R[l]
    d = LD[l]
    m = int(string2bin(d)) # converto una stringa in binario e poi in intero
    
    #print("[DEBUG] q-m",q-m,"q",q,",m: ",m, "pow(g,q-m,p)",pow(g,q-m,p), "pow(g,-m,p) ",pow(g,-m,p))
    print("[DEBUG] pow(g,m,p)*pow(g,q-m,p)%p",pow(g,m,p)*pow(g,q-m,p)%p, "pow(g,q,p) ",pow(g,q,p))
    
    if ZKP(x=r,g=h,p=p,q=q,y=(int(c)*pow(g,q-m,p) % p) ) == True: # pow(g,q-m,p) == pow(g,-m,p)
      print("[... ZKP of the knowledge of the secret {0} is verified]".format(l))
    else:
      print("[... ZKP of the knowledge of the secret {0} is NOT verified]".format(l))
      return False
  return True