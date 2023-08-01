from common_functions import *
#from feature2 import *

def generate_fake_server_db():
  with open('server/serverDB.csv', 'w', newline='') as csvfile:
    fieldnames = ['UN','hash_UID_SALT','salt','saldo']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    #writer.writerow()


def server_feature3_phase1_t0(GP,username):
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
  
  with open('server/serverDB.csv', newline='') as playersDB:
    reader = csv.DictReader(playersDB)
    for row in reader:
      if row['UN'] == username:
        print("[... User already registered]")
        return False
  
  return True

def store_player(username,GP,n,saldo):
  # Open the CSV file in "append" mode
  with open('server/serverDB.csv', 'a', newline='') as f: 
    # Create a dictionary writer with the dict keys as column fieldnames
    salt = prg(n)
    row = {'UN':username,'hash_UID_SALT': sha256( int(GP['UID']+str(salt)) ),'salt':salt,'saldo':saldo}
    writer = csv.DictWriter(f, fieldnames=row.keys())
    # Append single row to CSV
    writer.writerow(row)


def client_server_feature3_phase1_t1(SK_pedersen):
  """SK: Chiave privata del player che sta eseguendo il protocollo """
  (x,y,p,q,g,h) = SK_pedersen
  return ZKP(x,g,p,q,y)

def client_server_feature3_phase1_t2(SK_pedersen,GP,R,LD, L):
  """SK: Chiave privata del player che sta eseguendo il protocollo """
  (x,y,p,q,g,h) = SK_pedersen
  for l in L:
    c = GP[l]
    r = R[l]
    d = LD[l]
    m = int(string2bin(d)) # converto una stringa in binario e poi in intero

    if ZKP(x=r,g=h,p=p,q=q,y=(int(c)*pow(g,q-m,p) % p) ) == True:
      print("[... ZKP of the knowledge of the secret {0} is verified]".format(l))
    else:
      print("[... ZKP of the knowledge of the secret {0} is NOT verified]".format(l))
      return False
  return True

def server_feature3_phase1_t3(username,GP,n):
  store_player(username,GP,n,0)


def server_feature3_phase2_t0(GP,username):
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

def client_server_feature3_phase2_t1(SK_pedersen):
  """SK: Chiave privata del player che sta eseguendo il protocollo """
  (x,y,p,q,g,h) = SK_pedersen
  return ZKP(x,g,p,q,y)

def client_server_feature3_phase2_t2(SK_pedersen,GP,R,LD, L):
  """SK: Chiave privata del player che sta eseguendo il protocollo """
  (x,y,p,q,g,h) = SK_pedersen
  for l in L:
    c = GP[l]
    r = R[l]
    d = LD[l]
    m = int(string2bin(d)) # converto una stringa in binario e poi in intero

    if ZKP(x=r,g=h,p=p,q=q,y=(int(c)*pow(g,q-m,p) % p) ) == True:
      print("[... ZKP of the knowledge of the secret {0} is verified]".format(l))
    else:
      print("[... ZKP of the knowledge of the secret {0} is NOT verified]".format(l))
      return False
  return True



def check_player(username,GP):
  # Open the CSV file in "append" mode
   with open('server/serverDB.csv', newline='') as source:
    reader = csv.DictReader(source)
    for row in reader:
      if(row['UN'] == username): #If the person is found
        salt = row['salt']
        h_new = sha256( int(GP['UID']+str(salt)))
        if(h_new == row['hash_UID_SALT']):
          print("[... {0} is verified]".format(username))
          return True
    return False
    



def server_feature3_phase2_t3(username,GP,n):
  return check_player(username,GP)


