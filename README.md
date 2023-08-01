# APS_Project
For the implementation of the three functionalities of the APS's project, it was decided to use the Python 3.10 programming language, which, if necessary, invokes shell commands defined in the OpenSSL v 3.1.0 library.
The software produced is responsible for implementing the functionality extensively described in the previous Work Packages. However, the purpose of the code produced is exclusively to show the correct functioning of the features and not to realise an actual client-server software application. For this reason, the code produced simulates communication between the various actors in the system, assuming that each exchange of information only takes place within a secure channel between the two actors' endpoints. This layer, which was only assumed in the code, is in reality realised by the TLS protocol.  

## Code organization
The code is organised into directories and files:
- The directories named after an actor represent the secret information known to that actor:
o CA: contains all the directories and files necessary for the Certificate Authority to issue certificates.
o Player: contains its secret key and its green pass.
o MS: contains its secret key and various files that store user data and the list of Green Passes.
o Server: contains its secret key and a file storing the betting shop's user data.
- The 'Common' directory contains all public information, i.e. the public keys of the players and digital certificates.
- The Python files (featureX.py) include the functions required to implement the functionality provided by the protocol. It was decided to create three Python files, one for each feature to be implemented. The code is self-documenting because the name of each function has the following format: NameActor_featureX_phaseY_TZ, which specifies the actor executing the function, the feature referred to, the phase and the time of the protocol in which the function is to be called. Functions, in general, take as input the data necessary to perform the action envisaged at a given time by the protocol and which the actor in question knows. The output of the functions may be data produced by the actor's action, or the result of checks on the veracity of the data received as input (e.g. "return Verify(...)" ).
- The implementation includes a main program "main.py" which manages all the phases of the different protocols and simulates the communication between the different players, the Ministry of Health and the server by providing the individual entities with all the data essential to perform the intended action. The three functionalities are executed in sequence: first the players obtain a green pass from the Ministry of Health, then they use it to register with the S server and access it, then they open the information contained on the green pass to the server and finally the feature of extracting a random number as described in WP2 is executed.
- The file dsaparam.pem is the only file that is not generated each time the code is executed. This file contains the parameters necessary for the generation of the DSA keys, used for the Pedersen commitment, with a p-size of 2048 bits and a q-size of 256 bits. This file is already present in the project because OpenSSL version 3.2.0 was used to generate it. This version, in fact, allows the number of bits of the first q to be specified in addition to the number of bits of the first p.
# Requirements
In order to execute the code, it is required to run the 'main.py' script from the project's root directory (i.e. the one containing the 'main.py' file). The Python version required is 3.10 and the OpenSSL 3.1.0 library must be installed and its binaries included in the PATH environment variable.
