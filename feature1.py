from common_functions import *

N=64 #lunghezza random
players=[]
sigmas=[]
commits=[]
r_players=[]
sigma_r_C_players =[]
K_P={}
sigma_player_i=[]
commit_feature1_rand_player_i=[]
rand_player_i=[]
sigma_r_C_player_i=[]
R_P_i=[]



#generazione chiavi da fare a ogni partita 
def gen_key_for_player(indice_player):
    shell("openssl genpkey -paramfile common/prime256v1.pem -out player{0}/ecdsa_key.pem".format(indice_player))
    shell("openssl pkey -in player{0}/ecdsa_key.pem -pubout -out common/player{0}_ecdsa_key.pem".format(indice_player))
    PK= shell("cat common/player{0}_ecdsa_key.pem".format(indice_player)).decode("utf-8")
    SK= shell("cat player{0}/ecdsa_key.pem".format(indice_player)).decode("utf-8")
    return PK,SK

def delete_context(numero_di_player):
    for i in range(numero_di_player):
        shell("rm -r player{0}".format(i))

def client_feature1_phase1_T1(indice_player):
    PK,SK= gen_key_for_player(indice_player)
    return PK,SK

def server_feature1_phase1_T1(PK_player):
    players.append(PK_player)
    return players
    
# input tupla di tutti i player, PK propria ed SK propria
def client_feature1_phase1_T2(PK,SK):
    if(PK not in players):
        print("PK player non presente nella tupla inviata dal server")
        return
    sigma= hash_and_sign(SK,players)
    return sigma

def server_feature1_phase1_T2(sigma_player):
    sigmas.append(sigma_player)
    for i in range(len(sigmas)):
        v=vrfy(players[i], players, sigmas[i])
        if v is False:
            return


def client_feature1_phase1_T3():
    for i in range(len(sigmas)):
        v=vrfy(players[i], players, sigmas[i])
        if v is False:
            return
        
def client_feature1_phase2_T1(N):
    r=prg(N*2)
    c=sha256(r)
    return c,r

###server mette suo contributo alla fine di tutto manca perchè
    # come append per ogni palyer non riesco a fare ciò, non starebbe alla fine
def server_feature1_phase2_T1_aggregate_commit(commit_player):
    commits.append(commit_player)

def server_feature1_phase2_T1(N, SKs):
    rs=prg(N*2)
    cs=sha256(rs)
    commits.append(cs)
    sigma_c_p=hash_and_sign(SKs,players+commits)
    return sigma_c_p,rs
    
# input c è quella del player
def client_feature1_phase2_T2( c, PKs, sigma_c_p,SK,r):
    if c not in commits:
        print("c player non presente nei commit inviata dal server")
        return
    v=vrfy(PKs, players+commits, sigma_c_p)
    if v is False:
        print("c'è un errore")
        return
    sigma_r_C_player= hash_and_sign(SK,str(r)+str(commits))
    return sigma_r_C_player

def server_feature1_phase2_T2_aggregate_randomness_sigma(r_player,sigma_r_C_player):
    r_players.append(r_player)
    sigma_r_C_players.append(sigma_r_C_player)
    

def server_feature1_phase2_T2(r_s):
    r_players.append(r_s)
    
        
    for i in range(len(commits)-1): #ultimo è quello del server
        if(sha256(r_players[i]) != commits[i]):
            print("player ha commitato r diversa")
            return
    
    for i in range(len(sigma_r_C_players)):
        v= vrfy(players[i], str(r_players[i])+ str(commits), sigma_r_C_players[i])
        if v is False:
            return
        
def server_feature1_phase2_T3(SKs):
    temp_sigma=list_encode_bytes_to_base64(sigma_r_C_players)
    sigma_final=hash_and_sign(SKs, r_players + temp_sigma + commits)
    R=r_players[0]
    for i in range(len(r_players)-1):
        R=R ^ r_players[i+1] #xor python
    R = R >> N
    return sigma_final,R
    
def client_feature1_phase2_T3(PKs, sigma_final):
    
    temp_sigma=list_encode_bytes_to_base64(sigma_r_C_players)
    v=vrfy(PKs, r_players+ temp_sigma + commits, sigma_final)
    if v is False:
        return
    for i in range(len(r_players)):
        if(sha256(r_players[i]) != commits[i]):
            print("player ha commitato r diversa")
            return
    for i in range(len(sigma_r_C_players)):
        v=vrfy(players[i], str(r_players[i])+str(commits), sigma_r_C_players[i])
        if v is False:
            print(v)
            return
    R=r_players[0]
    for i in range(len(r_players) -1):
        R=R ^ r_players[i+1] #xor python
    R = R >> N
    return R
