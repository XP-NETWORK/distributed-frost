
use std::io::Read;
use std::usize;
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(not(feature = "std"))]
use core::cmp::Ordering;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use frost_secp256k1::{Participant,Parameters,DistributedKeyGeneration,GroupKey,
    IndividualPublicKey,IndividualSecretKey,SignatureAggregator,compute_message_hash,
    precomputation::{CommitmentShare,PublicCommitmentShareList},
    signature::{Aggregator,PartialThresholdSignature,Signer},keygen::{SecretShare}
};
use frost_secp256k1::keygen;
use frost_secp256k1;
use k256::{AffinePoint,PublicKey,Scalar,Secp256k1,SecretKey,
    elliptic_curve::{ScalarArithmetic,group::{GroupEncoding}
    }
};

use rand::rngs::OsRng;
use rand::seq::index;
use sec1::point;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::Write;
use serde;
use std::convert::TryInto;
use k256::ecdsa::Signature;

use core::convert::TryFrom;
use generic_array::GenericArray;
use generic_array::typenum::Unsigned;
use crate::frost_secp256k1::generate_commitment_share_lists;
//Comvert the contents of a file into a vector of string to mimic read lines one by one 
//
fn lines_from_file(filename: &str) -> Vec<String> {
    let mut inputfile = match File::open(filename) {
        Ok(inputfile) => inputfile,
        Err(_) => panic!("no such file"),
    };
    let mut file_contents = String::new();
    inputfile.read_to_string(&mut file_contents)
        .ok()
        .expect("failed to read!");
    let lines: Vec<String> = file_contents
        .split("\n")
        .map(|s: &str| s.to_string())
        .collect();
    lines
}
// The secret Vector of  particpant to be converted to bytes 
// These secrets are to be shared with other parties . 
// Before proceeding to the Round one every party must collect Secret shares created by all other parties for self
// and create a Vector of secret shares with all secret shares from all parties destined for self
//In configuration of 11 Parties, each party will get 10 SecretShares
// Size of one SecretShare is 44 bytes . so total size would be 440

fn convert_secret_to_bytes(secretvector: &Vec<SecretShare>)->[u8;440]
{
    //Structure of one Secretbytes is Index and polynomial_evaluation which is a Scaler ( 40+4)
    // Direct Constructor for polynomial_evaluation ( Scaler) is not present so we 
    // serialize it with bincode instead of using to bytes function which return the sec bytes
    // and adding index manually
    // every secret share is 44 bytes long s

    let total=secretvector.len();
    let mut count=0;
    let mut secretbytes: [u8;440]=[0;440];
    let mut startindex=0;
    let mut endindex=0;
    
    // loop through all bytes and calculating the size of next location
    //  by getting the length and adding it in the start index

    while count<total
    {   
        let writebytes: Vec<u8>=bincode::serialize(&secretvector[count]).unwrap();
       // convert secret vector[count] to bytes using bincode instead of to bytes function
        let size: usize =writebytes.len();
        endindex=endindex+size;
        secretbytes[startindex..endindex].copy_from_slice(writebytes.as_slice());
         count=count+1;
        startindex=endindex;

    }
    secretbytes
}

// Cinverting Bytes back to secret Vector of  particpant 
// These secrets are to be shared with other parties. 
// Before proceeding to the Round one every party must collect Secret shares created by all other parties for self
// and create a Vector of secret shares with all secret shares from all parties destined for self
//In configuration of 11 Parties, each party will get 10 SecretShares
// Every Secret share is a vector contaning 10 Secrete shares in the configuration of 11 parties
fn convert_bytes_to_secret(secretbytes:[u8;440] )->Vec<SecretShare>
{
    //Structure of one Secretbytes is Index and polynomial_evaluation which is a Scaler ( 40+4)
    // Direct Constructor for polynomial_evaluation ( Scaler) is not present so we 
    // DEserialize it with bincode which return the secret SHare 
    // and pushing it to the Secret vector 
       
    let mut secret_vector_from_bytes :Vec<SecretShare>=vec![];
    
     let mut startindex=0;
     let mut endindex=44;
     let total=11;
     let mut count=1;
     while count<total
    {   
        let mut bytesvalues: [u8;44]=[0;44];
        // Initialize 44 bytes to zero and copy from the input from start index to end index 
        // which will be looping through starting from [0..44]
        bytesvalues.copy_from_slice(&secretbytes[startindex..endindex]);
        // Create a clone secret share by deserializing it using bincode
        let clone_secret_share: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&bytesvalues);
        // unwrap the secretshare and push it on the secretvector to be returned.
        //for a party of 11 the vector will have a size of 10. 
        secret_vector_from_bytes.push(clone_secret_share.unwrap());
         // swap the end index with start index and increade endindex by 44       
         startindex=endindex;
         endindex=endindex+44;
         count=count+1;

    }  
    secret_vector_from_bytes

}


fn main() {

    let mut name = String::new();
    let mut threholdvalue :u32=7;
    let mut totalvalue :u32=3;
    let mut id: u32 = 1;
    
    println!("Kindly enter Current party value");
    let _=std::io::stdin().read_line(&mut name);
    // read params from file and assign them to id line0, thres line1 and totalvalue line2
    let lines = lines_from_file("src/params.txt");
    id =lines[0].trim().parse().unwrap();
    threholdvalue=lines[1].trim().parse().unwrap();
    totalvalue=lines[2].trim().parse().unwrap();
    //id=name.trim().parse().unwrap();  
    println!("id ={} , thresh={},total={}", id.to_string(), threholdvalue.to_string(), totalvalue.to_string());
  
    // create Directory for file 
    let mut pathfile = String::from("/opt/datafrost/") + lines[0].to_string().trim() + "/";
    let _res=fs::create_dir(&pathfile);
    let mut publickeytofile = pathfile + "public" + &lines[0].to_string() + ".txt";
    //fs::remove_file(&publickeytofile).expect("could not remove file");
    let mut data_file = File::create(publickeytofile).expect("creation failed");

    // Create Participant using parameters
    let params = Parameters { n: totalvalue, t:threholdvalue };
    let   (mut party, _partycoeffs) = Participant::new(&params, id);
    //_partycoeffs are never to shared as these act as the private key for participant in 
    // forwarding the Distributed keygeneration algorith 
    //Convert Public key to bytes for writting and distrbution.
        let public_bytes =party.public_key().unwrap().to_bytes();
        let _file_write_result=data_file.write_all(&public_bytes);
        // Create public key file in the designated folder
        let mut public_key_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/public" + id.to_string().trim()+ ".txt";
        
        let mut public_file = match File::open(&public_key_filepath) {
            Ok(public_file) => public_file,
            Err(_) => panic!("no such file"),
        };
        
        let mut bufferfile: [u8;33]=[0;33];
          let _ = public_file.read_exact( &mut bufferfile);
             // Convert Self Participant  Party to bytes to write to file 
            // These 315 bytes will be shared between all parties.
        let bytes_committed=convert_party_to_bytes(&id, &party, &party.proof_of_secret_key);
      
         let participantvectorpath = String::from("/opt/datafrost/") +&lines[0].to_string()+ "/participantvector" + &lines[0].to_string() + ".txt";
            println!("Verify the Participantvectorbinary file at {}",&participantvectorpath);
    
            fs::remove_file(&participantvectorpath).expect("could not remove file");
         let mut data_filecommit = File::create(&participantvectorpath).expect("creation failed"); // writing 
         let result_file_write=data_filecommit.write_all(&bytes_committed);
                // Convert original party to 32 bytes party with z value zero 
         let partyconv=convert_bytes_to_party(&bytes_committed);
         // The original Public key and Project points contains z which is now converted to [1 0 0 0 0]
         // Cloning original party from converted party to avoid error in group key later. 
         // doing it for all parties so that all parties have their Z converted so it doesnt count in rest of calculations
         party.clone_from(&partyconv);
    
                 std::io::stdin().read_line(&mut name);
        // Create a party vector to store all other participant vectors . Since id's of Participant 
        // start from 1 
        let mut  other_Party_vectors: Vec<Participant>= vec!();
        
        let mut counter_party=1;
       // other_Party_vectors.clear();
       // Get shares from all party vectors 
        while (counter_party<12)
        {
          
            if counter_party==id
            {
                // if this loop counter is equal to own id , Dont have to store it in other participant vectors
                println!("Do nothing for self Participant vector ");
            }
            else 
            
            {
                let  path_to_read_party_vector = String::from("/opt/datafrost/") +&counter_party.to_string()+ "/participantvector" + &counter_party.to_string() + ".txt";
                let mut party_file = match File::open(&path_to_read_party_vector) {
                    Ok(party_file) => party_file,
                    Err(_) => panic!("no such file"),
                };
               // println!("{:?}",path_to_read_party_vector);
                let mut result_bytes_from_file:[u8;315]=[0;315];
                let _=party_file.read_exact(&mut result_bytes_from_file);

                    // create Participant vector from file for use 
                    let mut party_input=convert_bytes_to_party(&result_bytes_from_file);
                

                    if party_input.index==party.index
                    {
                        println!("Dont push self key {} to Other party vector ",party_input.index)
                    }
                    else
                    {
                        // push only those participant vectors which have index not equal to own id
                         other_Party_vectors.push(party_input);
                                       
                    }
                 
                }
                counter_party=counter_party+1;    
            }
        
        
        std::io::stdin().read_line(&mut name);

        let mut partystate=DistributedKeyGeneration::<_>::new(&params,&id,&_partycoeffs,&mut other_Party_vectors).or(Err(())).unwrap();

        let mut partyone_secrets: &Vec<SecretShare>=partystate.their_secret_shares().unwrap();


        let total_secret_shares=partyone_secrets.len();

      // full party 440 
            /*
            Full mode 11       
            ________________
            /.,------------,.\
            ///  .=^^^^^^^\__|\\
            \\\   `------.   .//
            `\\`--...._  `;//'
            `\\.-,___;.//'
                `\\-..-//'
            ZKP    `\\//'
                    ""
            */
                    
        //Write own Share to file 
        
        let fullparty=convert_secret_to_bytes(partyone_secrets);

         let mut secret_share_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/party_secrets" + id.to_string().trim()+ ".txt";
         //1fs::remove_file(&secret_share_filepath).expect("could not remove file");
         let mut secret_file = File::create(&secret_share_filepath).expect("creation failed");
         let result=secret_file.write_all(&fullparty);
         println!("Checking all files are written with party scecrets");
         std::io::stdin().read_line(&mut name);
         

            // Start loop for retreiving secrets from all personnel
            // read all secret file vectors from other parties and select all secret shares with own id 
            let mut other_party_secret_shares: Vec<SecretShare>=vec!();
            let mut  file_nos=1;
            while file_nos<12
            {
            if file_nos==id
            {
                // no need to scan own file for own secret shares
                println!("no need to scan own file for own secret shares");
            }
            else {
            
            
             let mut secret_share_filepath = String::from("/opt/datafrost/")+ file_nos.to_string().trim()  + "/party_secrets" + file_nos.to_string().trim()+ ".txt";
             let mut file = match File::open(&secret_share_filepath) {
                 Ok(file) => file,
                 Err(_) => panic!("no such file"),
                };

            let mut secret_bytes : [u8;440]=[0;440];
            file.read_exact(&mut secret_bytes);
            let mut shared_vector=convert_bytes_to_secret(secret_bytes);
            // find shares belonging to self from file 
            let mut vari_count=0;
            while (vari_count<shared_vector.len()+1)
            {//println!("going through this file {}",secret_share_filepath);
                if shared_vector[vari_count].index==id
                {
                    other_party_secret_shares.push(shared_vector[vari_count].clone());
                    
                    break; // only one entry of self in any shared secret vector file
                }
                vari_count=vari_count+1;
            }
        } // else 
                file_nos=file_nos+1;
                
            } // while reading all files

           
            let  partystate2: DistributedKeyGeneration<keygen::RoundOne>=partystate.clone();
        
            let  partystaternd2: Result<DistributedKeyGeneration<keygen::RoundTwo>, ()> = partystate2.clone().to_round_two( other_party_secret_shares);
            
            let partystaternd2: DistributedKeyGeneration<keygen::RoundTwo>=partystaternd2.unwrap();
    
            let mut partyfinale=partystaternd2.finish(&party.public_key().unwrap()).unwrap();
            
            //let mut partysecretkey=blabblabbalb.as_mut().unwrap().1;
            println!("Groupkey");
            println!("{:?}",partyfinale.0);
            
    
             println!("Secret key full ");
              println!("{:?}",&mut partyfinale.1);
            // println!("{:?}",&mut blabblabbalb.1);
             println!("Public key from Private key ");
             println!("{:?}",&mut partyfinale.1.to_public());
             
             println!("Groupkey bytes");
             println!("{:?}",partyfinale.0.to_bytes().len()); 
             println!("Secret key bytes ");
             println!("{:?}",partyfinale.1.key.to_bytes().len());
             println!("Public key bytes ");
             println!("{:?}",partyfinale.1.to_public().share.to_bytes().len());

             let _=std::io::stdin().read_line(&mut name);
    
    // need for signing 
/*
    Create steps for signing . party 1 will act as signing validator
                ================================================.
                    .-.   .-.     .--.                          |
                    | OO| | OO|   / _.-' .-.   .-.  .-.   .''.  |
                    |   | |   |   \  '-. '-'   '-'  '-'   '..'  |
                    '^^^' '^^^'    '--'                         |
                ===============.  .-.  .================.  .-.  |
                               | |   | |                |  '-'  |
                               | |   | |                |       |
                               | ':-:' |                |  .-.  |
                Sleepy         |  '-'  |                |  '-'  |
                ==============='       '================'       |


            
 */
  
        let context = b"CONTEXT STRING FOR XP NFT BRIDGE TEST FOR APPLE>D>HAIDER>SMITH";

        let message = b"This is a test message from Xp Bridge piece Meal 20230815";
        
        //Create 
        // Set flag for leader so that Leader among the nodes know 
        // that he is the signature agregator in the case
        // Lead will do the aggregator call and share commitment shares for others to see. 
        // The leader will loop through all public commitments consisiting of 70 bytes by other signers         
        //  70 bytes = Affine point 1 (33 bytes) + Affinepoint 2 ( 33 bytes ) and index of the party ( 4 bytes)       
        //  The lead will include all the4se  commitments in the aggreagator along with public key, index id        
        //  This will generate the signer vector and every party has to go through it and get its corresponding id  from signer  vector
        // 

        let leader:bool=true;

        if leader==true
        {

        

        let (mut agg_Party_commshare, mut agg_secret_comshares) = generate_commitment_share_lists(&mut OsRng, id, 1);
        // let signerres=aggregator.get_signers();
        println!("Inside agregator loop  ");       
        println!("Theshold Signature Step-1 : Creating Signature Aggregator with context, message, params and group key ");
         let mut aggregator=SignatureAggregator::new(params,partyfinale.0,context.to_vec(),message.to_vec());
                     
         let bytesoff: [u8; 70] =public_commitment_to_bytes(&agg_Party_commshare);

         // write commitment share and public key in files
         let mut public_comshare_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/public_comshares" + id.to_string().trim()+ ".txt";
       //  fs::remove_file(&public_comshare_filepath).expect("could not remove file");
         println!("{}",public_comshare_filepath);
         let mut public_comm_share_file = File::create(&public_comshare_filepath).expect("creation failed");
         let result=public_comm_share_file.write_all(&bytesoff);
         
         let mut public_keyshare_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/public_final_key" + id.to_string().trim()+ ".txt";
       //  fs::remove_file(&public_comshare_filepath).expect("could not remove file");
         println!("{}",public_keyshare_filepath);
         let mut public_key_final_file = File::create(&public_keyshare_filepath).expect("creation failed");
         
         let result=public_key_final_file.write_all(&partyfinale.1.to_public().share.to_bytes());
         println!("Theshold Signature Step-2 : Public Commitment share 70 bytes written ");
         std::io::stdin().read_line(&mut name);
         //PublicKey::from_sec1_bytes(bytes)
         //partyfinale.1.to_public().share.to_bytes()
         let  final_GroupKey: GroupKey= partyfinale.0;
         let  partynew=partyfinale;
    
         let message_hash = compute_message_hash(&context[..], &message[..]);
       //  let signers = aggregator.get_signers();
         
         // loop through all other files for commitment and public key 
         let mut count=2;
         while count <12
         {
             let mut public_comshare_filepath = String::from("/opt/datafrost/")+ count.to_string().trim()  + "/public_comshares" + count.to_string().trim()+ ".txt";
             let mut bytespublicexact: [u8; 70]=[0;70];
             let mut file_pub = match File::open(&public_comshare_filepath) {
                 Ok(file_pub) => file_pub,
                 Err(_) => panic!("no such file"),
                };
              file_pub.read_exact(&mut bytespublicexact);
              println!("Theshold Signature Step-5 : Reading Public Comm share to create Signer Vector  ");
              println!("Reading Public Comm share for Party id {}",count);
                        
             let comms=public_bytes_to_commitment(bytespublicexact);
            

             // get commitment share list from bytes

             let mut public_keyshare_filepath = String::from("/opt/datafrost/")+ count.to_string().trim()  + "/public_final_key" + count.to_string().trim()+ ".txt";
             let mut bytespublickey: [u8; 33]=[0;33];
             let mut file_pubkey = match File::open(&public_keyshare_filepath) {
                 Ok(file_pubkey) => file_pubkey,
                 Err(_) => panic!("no such file"),
                };
              file_pubkey.read_exact(&mut bytespublickey);

                println!("{:?}",bytespublickey);
              let mut genarraypublic=GenericArray::from_slice(&bytespublickey);
              println!("{:?}",genarraypublic);

              let pk_sk_affinepoint=AffinePoint::from_bytes(genarraypublic);
              let pk_sk_affinepoint=pk_sk_affinepoint.unwrap();
              partynew.1.to_public().share.clone_from(&pk_sk_affinepoint);

               let publickey_party_count=PublicKey::from_affine(pk_sk_affinepoint).unwrap();
             
             let alpha : IndividualPublicKey=IndividualPublicKey { index: count, share: pk_sk_affinepoint };
             let xyz=PublicKey::from_affine(pk_sk_affinepoint);
             let xyz= xyz.unwrap();

             aggregator.include_signer(count, comms.commitments[0],alpha);     
          
              count=count+1;

         }


           let signers: &Vec<frost_secp256k1::signature::Signer> = aggregator.get_signers();
           

         println!("{:?}",signers);
         println!("{:?}",signers.capacity());
         println!("Stop here for the signer vector ");
         std::io::stdin().read_line(&mut name);
         let indexsign=0;

         let bytessamoke =signer_vector_ten_tobytes(signers, indexsign);
         println!("{:?}",bytessamoke);
         println!("{:?}",signer_bytes_to_ten_vector((bytessamoke)));
         let mut signer_700_file = String::from("/opt/datafrost/")+ "signer_vector_700" + ".txt";
         //  fs::remove_file(&public_comshare_filepath).expect("could not remove file");
           //println!("{}",public_keyshare_filepath);
           let mut signer_file_writer = File::create(&signer_700_file).expect("creation failed");
           let _=  signer_file_writer.write_all(&bytessamoke);
             println!("signer bytes written ");
             println!( "go ahead on signers for writing Partial signatures aggreagotr party ");
             println!( "Waiting for all other parties to write TSS ");
             println!("Theshold Signature Step-6 : Waiting for Signers to generate Tss against signer vector  ");
                   let _=   std::io::stdin().read_line(&mut name);
                    let mut counttss=2;
                      while counttss <12
                      {
                        let mut partial1: [u8; 44]=[0;44];
                         let mut count=2;      
                      let mut public_tss = String::from("/opt/datafrost/")+ counttss.to_string().trim()  + "/tss" + counttss.to_string().trim()+ ".txt";
                      
                         let mut tss_signer = match File::open(&public_tss) {
                             Ok(tss_signer) => tss_signer,
                             Err(_) => panic!("no such file"),
                                 };
                           let _= tss_signer.read_exact(&mut partial1);

                          println!( " Theshold Signature Step-9.1: read Partial sig from file for {} signer and converted backfrom bytes",counttss+1);
                             // create partial sign
                             let partial_sign1=partialsig_from_bytes(partial1);// create partial sign
                             println!("Tss for index id {} is  {:?}",partial_sign1.index,partial_sign1.z);
                                  aggregator.include_partial_signature(partial_sign1);

                             counttss=counttss+1;   
                         }

            let aggregator_finalized = aggregator.finalize().unwrap();
                   println!("at aggregator function wih TSS unwrap");
                   println!( " Theshold Signature Step-11: Aggregating Finalizing");
            let  threshold_signature_final: Result<frost_secp256k1::ThresholdSignature, std::collections::HashMap<u32, &str>>  = aggregator_finalized.aggregate();


                        //let valuebytes=threshold_signature_final.unwrap().to_bytes();     
     println!("Theshold Signature Step 12 .  wih TSS unwrap");
     if threshold_signature_final.is_ok()
     {
         //threshold_signature=threshold_signature.unwrap();
         println!("{:?}",threshold_signature_final.as_ref().unwrap().to_bytes());
         println!("Threshold okay");

     }
     
     println!("Group key {:?}",final_GroupKey);
     println!("Group key for party new {:?}", partynew.0);
     
     let verification_result = threshold_signature_final.unwrap().verify(&final_GroupKey
         , &message_hash);
     println!("Theshold Signature Step 13 at verification.  wih TSS unwrap");
     if verification_result.is_ok()
     {
         //println!("{:?}",threshold_signature_final.as_ref().unwrap().to_bytes());
         println!("TSS signature verified for message hash {:?}",message_hash );
     }

     }
     else {
         // for  rest of 7/11 other parties
         // Generate Commitment share lists for one time use using RNG and own id
         let (mut other_Party_commshare, mut other_party_secret_comm_share) = generate_commitment_share_lists(&mut OsRng, id, 1);
         //let (any_public_comshares, mut any_secret_comshares) = generate_commitment_share_lists(&mut OsRng, id, 1);
         // write commitment share and public key in files

         println!("Theshold Signature Step-3 : Generating Commitment shares for one time use ");
         let message_hash = compute_message_hash(&context[..], &message[..]);
      //   let party_partial = partyfinale.1.sign(&message_hash, &partyfinale.0,&mut other_party_secret_comm_share,0,&signers).unwrap();
          let mut public_comshare_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/public_comshares" + id.to_string().trim()+ ".txt";
      
        println!("{}",public_comshare_filepath);
        let mut secret_file = File::create(&public_comshare_filepath).expect("creation failed");
        let bytesoff: [u8; 70] =public_commitment_to_bytes(&other_Party_commshare);
        let _result=secret_file.write_all(&bytesoff);
        
        let  public_keyshare_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/public_final_key" + id.to_string().trim()+ ".txt";
      
        println!("{}",public_keyshare_filepath);
        let mut secret_file = File::create(&public_keyshare_filepath).expect("creation failed");
        
        let _result=secret_file.write_all(&partyfinale.1.to_public().share.to_bytes());
        
        println!( "Public shares Written with Comm shares.  ");
        println!("Theshold Signature Step-4 : Commitment shares written for use by Aggregator ");
        println!( "Waiting for Aggreagator GO Ahead to send signer vector  ");
               let _ = std::io::stdin().read_line(&mut name);

        //read signers vector from file 
        let  signer_vector_700 = String::from("/opt/datafrost/")+ "signer_vector_700" + ".txt";
        let mut signer_700_bytes: [u8; 700]=[0;700];
             let mut file_signer = match File::open(&signer_vector_700) {
                 Ok(file_signer) => file_signer,
                 Err(_) => panic!("no such file"),
                };
                let _=  file_signer.read_exact(&mut signer_700_bytes);
                println!( " Theshold Signature Step-7: Retreived Signer 700 bytes to create TSS ");
                
                let signer_700_from_file=signer_bytes_to_ten_vector(signer_700_bytes);
        let party_partial = partyfinale.1.sign(&message_hash, &partyfinale.0,&mut other_party_secret_comm_share,0,&signer_700_from_file).unwrap();
                println!("{:?}",signer_700_from_file);
                println!("{:?}", party_partial);
                let output: [u8; 44]=partialsig_to_bytes(party_partial);
                let newtss=partialsig_from_bytes(output);
                println!("writign partial signature to file ",);

                let mut public_tss = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/tss" + id.to_string().trim()+ ".txt";
                //  fs::remove_file(&public_comshare_filepath).expect("could not remove file");
                  println!("{}",public_tss);
                  let mut tss_file = File::create(&public_tss).expect("creation failed");
                  let result=tss_file.write_all(&output);
                  println!( " Theshold Signature Step-8: Created Tss for Party  id {} ", id);
                  println!( "Work for Party id {}  completed  ", id);

                let _=std::io::stdin().read_line(&mut name);
                let _=std::io::stdin().read_line(&mut name);
                //let newtss=partialsig_from_bytes(output);
                //println!("{:?}", newtss);
     }

//close the keygen


// Function to convert Participant vector to bytes which contains , 
//Scaler R and S along with index of Party and Commitment shares. 
// The value of commitment share count is dependent upon the set threshold, 
// which in this case is 7
//The function is only applicable for frost with parameters of 7/11 where 7 is  (Threshold) and 11( total parties) 
fn convert_party_to_bytes(index: &u32, commitments_party: &frost_secp256k1::Participant,zkp:&frost_secp256k1::nizk::NizkOfSecretKey) -> [u8;315]
{
        // Return bytes of count 315
        // Structure of bytes
        // ZKP R scaler 40 bytes
        // ZKP S scaler 40 bytes
        // 7 Commitments shares 33 bytes=231
        // index u32 ->u8 = 4 bytes
        // Total=40+40+33+33+33+33+33+33+33+4=315 
        // Create a fixed size byte array of 315 size to return 
    let mut resultbytes:[u8;315]=[0;315];
    
    //No direct method is available to Prepare Scalers back from bytes 
    //so an indirect method was derived and the serialization code 
    // of bincode was used to serialze Scaler  and vice versa.
    //The only draw back is that the size of original scaler is 32 bytes while converting it 
    // using bincode makes it 40 bytes. 
    
    let rbytes=bincode::serialize(&zkp.r).unwrap();
    let split=rbytes.split_at(40);
    resultbytes[0..40].clone_from_slice(&split.0);
    //copy R bytes to resulant bytes at the start of byte array
    let sbytes=bincode::serialize(&zkp.s).unwrap();
    let split=sbytes.split_at(40);
    resultbytes[40..80].clone_from_slice(&split.0);
    //copy S bytes to resulant bytes at the specified location 
    // Total commitments are 7 in our case due to theshold
    let mut commit_count=0;
    let mut startin_byte_index=80;
    // start loop to copy all commitment vectors to resulant bytes
    while commit_count<7
    
    {   // Each commitment is 33 bytes long but to be sure that no ir-regular 
        // data is copied only 33 bytes are split from the usized byte array into 
        // generic array and then using the split function are split at specified size . 
        //Resulting 33 bytes are cloned  from slice. 
        let ending_index=startin_byte_index+33;
        let commitmentbytes=commitments_party.commitments[commit_count].to_bytes();
        let commit_split=commitmentbytes.split_at(33);
        resultbytes[startin_byte_index..ending_index].clone_from_slice(commit_split.0);
        startin_byte_index=ending_index;
        commit_count=commit_count+1;

    }
    // copy index bytes in the resultant buffer
    resultbytes[startin_byte_index..315].copy_from_slice(index.to_be_bytes().as_slice());
    //return resultbytes
    resultbytes
}
pub struct ZKPSecretKey {
    /// The scalar portion of the Schnorr signature encoding the context.
    pub s: Scalar,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    pub r: Scalar,
}

// Function to convert Participant vector from bytes to Particpant object 
// This function is for frost with parameters of 7/11 where 7 is  (Threshold) and 11( total parties) 
fn convert_bytes_to_party(party_bytes: &[u8;315]) -> (Participant)
{
    // Structure of bytes
        // ZKP R scaler 40 bytes
        // ZKP S scaler 40 bytes
        // 7 Commitments shares 33 bytes=231
        // index u32 ->u8 = 4 bytes
        // Total=40+40+33+33+33+33+33+33+33+4=315 
    // Create an empty commitment Vector 
    let mut commit_vector:Vec<k256::ProjectivePoint>=vec!();

    
    let mut bytes_sequence :[u8;4]=[0,0,0,0];
    bytes_sequence.clone_from_slice(&party_bytes[311..315]);

    
    // Since No direct conversion from u8 to u32 is available, 
    // we skim through 8 bytes and converting them during the process
    //  and convert u8 to u32 to form Index
    let index_u32_integer: u32 = ((bytes_sequence[0] as u32) << 24)
                    | ((bytes_sequence[1] as u32) << 16)
                    | ((bytes_sequence[2] as u32) << 8)
                    | (bytes_sequence[3] as u32);;
   
   // copy r and s bytes from slice 
   // to convert these bytes back into scaler using bincode
    let mut bytes_for_r: [u8;40]=[0;40];
    bytes_for_r.copy_from_slice(&party_bytes[0..40]);
    let mut bytes_for_s:[u8;40]=[0;40];
    bytes_for_s.copy_from_slice(&party_bytes[40..80]);
    
    // create S and R from De-Serializing bincode and  
          
    let  skey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(bytes_for_s.as_ref());
    let  rkey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(bytes_for_r.as_ref());
    // create a new Nizk of Secret Keys  with r and S for formation of participant
    // This Nizk is a ZKP which allows other parties to verify that the particpant is holder of private key / Secret Vector and 
    // susequently verfied Participant
    let mut zkpfull :frost_secp256k1::nizk::NizkOfSecretKey= frost_secp256k1::nizk::NizkOfSecretKey { s: skey.unwrap(), r: rkey.unwrap() };
    // Counter of Commitment so to loop through all 7 commitments
    
    let mut commit=0;
    // Starting size is 80 for commitment shares with 40 bytes for R and 40 bytes for S
    let mut start_bytes=80;
    
    
        // Counter of Commitment so to loop through all 7 commitments of size 3 3bytes

    while(commit<7)
    {
        let endvalue=start_bytes+33;
        // Each commitment is of 33 bytes which is actually a projective point with two scalers . 
        let mut bytescommit:[u8;33]=[0;33];

        
        
       // 33 bytes for creating a commitment for Commitment vector in Participant 
        bytescommit.copy_from_slice(&party_bytes[start_bytes..endvalue]);

        let mut genarray=GenericArray::from_slice(bytescommit.as_ref());
       // Create a Projective point from bytes with z [1,0,0,0,0]
        let mut byte_projective=k256::ProjectivePoint::from_bytes(&genarray).unwrap(); 
        // Push the prepared projective point on commitment vector 
        commit_vector.push(byte_projective);

        start_bytes=endvalue;
        commit=commit+1;

    }
    // Create a new participant with index, commitment vector and proof of secret key  from bytes 
        let  party_convert: Participant=Participant { index: index_u32_integer , commitments: commit_vector, proof_of_secret_key: zkpfull };


party_convert
}

    //function to convert  participant with R and S converted without bincode
    // fails to convert back due to no direct constructor available to create Scalers from bytes

}

pub struct PublicCommitShareListformain {
    /// The participant's index.
    pub participant_index: u32,
    /// The published commitments.
    pub commitments: Vec<(AffinePoint, AffinePoint)>,
}

    // Commitment share generated by each party after formation of group key.
    // This commitment share is used by signature aggregator /Leader 
    // to include in the signer vector .
    // Each commitment share consists of two affine points and index of the party 
    // Affine points when converted to bytes become 33 bytes so the total value of 
    // commitemnetshare is total 70 bytes 
    //= Affine point 1 (33 bytes) +
    // Affinepoint 2 ( 33 bytes ) +
    // index of the party ( 4 bytes) 

fn public_commitment_to_bytes(publiccomitmentsharelist:&PublicCommitmentShareList )->[u8;70] 
{
    // Struct 33 +33 +4 =70bytes
    // initialize return  bytes by 0 
    let mut returnbytes: [u8;70]=[0;70];
    // copy 33 bytes from converting first commitment affine point and stor them at location 0..33
    returnbytes[0..33].copy_from_slice(&publiccomitmentsharelist.commitments[0].0.to_bytes());
    // copy 33 more bytes from converting second commitment affine point 2 and store them at location 33..66
    returnbytes[33..66].copy_from_slice(&publiccomitmentsharelist.commitments[0].1.to_bytes());
    // copy index which is u32 . converted to u8 becomes 04 bytes 
    returnbytes[66..70].copy_from_slice(&publiccomitmentsharelist.participant_index.to_be_bytes());
    
    returnbytes    

}
// convert 70 bytes back to the Commitment share. 
// This Commitment share generated by each party after formation of group key.
// This commitment share is used by signature aggregator /Leader 
// to include in the signer vector .
// Each commitment share consists of two affine points and index of the party 
fn public_bytes_to_commitment(returnbytes:[u8;70] )->PublicCommitmentShareList
{
    
    let mut indexbytes:[u8;4]=[0;4];
    indexbytes.copy_from_slice(&returnbytes[66..70]);
    // create index directly from bytes to store in Commitment share list
    let indexcommit:u32=u32::from_be_bytes(indexbytes);
     // affine point 1 is converted from bytes 0..33 
     // the constructer of affine point requires generic array of u8 instead of sized array 
     // so the converted affine bytes are converted to genarray and 
     // which in turn is converted to affine point 1
     let mut affinebytes:[u8;33]=[0;33];
     affinebytes.copy_from_slice(&returnbytes[0..33]);
     let mut genarrya=GenericArray::from_slice(affinebytes.as_ref());
     let affine1 :AffinePoint=AffinePoint::from_bytes(&genarrya).unwrap();
      // affine point 2 is converted from bytes33..66 
     // the constructer of affine point requires generic array of u8 instead of sized array 
     // so the converted affine bytes are converted to genarray and 
     // which in turn is converted to affine point 2
     affinebytes.copy_from_slice(&returnbytes[33..66]);
     let mut genarrya=GenericArray::from_slice(affinebytes.as_ref());
     let affine2 :AffinePoint=AffinePoint::from_bytes(&genarrya).unwrap();
     
    // Commitment share list consists of tuple of affines inside of a vector so a new tuple of two affine
    // points is made and affine1 and affine2 are clone in it 
     let mut tuple: (AffinePoint, AffinePoint)=(affine1,affine2);
     tuple.0.clone_from(&affine1);
     tuple.1.clone_from(&affine2);
    // Vector of tuples is formed by pushing the tuple directly on the vector
     let mut vec_of_tuples = Vec::new();
     vec_of_tuples.push(tuple);
    // Constructor Public commitment share is run to 
    //prepare PublicCommitmentShareList and return it 
     let other_party_commshare=PublicCommitmentShareList { participant_index: indexcommit,commitments:vec_of_tuples  };
     
    other_party_commshare

}


fn partialsig_to_bytes(signtss:PartialThresholdSignature)->[u8;44]{
    let mut indexbytes:[u8;4]=signtss.index.to_be_bytes();
    let mut resultbytes: [u8;44]=[0;44];
    let bytesz=bincode::serialize(&signtss.z).unwrap();
    println!("{:?}",bytesz.len());
    let split=bytesz.split_at(40);
        resultbytes[0..40].clone_from_slice(&split.0);
        resultbytes[40..44].clone_from_slice(indexbytes.as_slice());

        resultbytes
    

}
fn partialsig_from_bytes(bytes:[u8;44])->PartialThresholdSignature{
   
    let mut indexbytes:[u8;4]=[0;4];
    indexbytes.copy_from_slice(&bytes[40..44]);
    
    let indexvalue=u32::from_be_bytes(indexbytes);
    let mut scalerbytes:[u8;40]=[0;40];
    
    scalerbytes.copy_from_slice(&bytes[0..40]);
    let zscaler: Result<Scalar, Box<bincode::ErrorKind>>=bincode::deserialize(scalerbytes.as_ref());
    println!("{:?}",&zscaler.unwrap());
    let mut zscaler: Result<Scalar, Box<bincode::ErrorKind>>=bincode::deserialize(scalerbytes.as_ref());
    let zscaler2=zscaler.unwrap();
    let returntss:PartialThresholdSignature=PartialThresholdSignature { index:indexvalue, z: zscaler2 };
    
returntss
    
}

// Convert Signer vector to bytes for use by all Signers. 
// These vectors are generated by Signature aggregators and only to be used by specific signers 

fn signer_vector_ten_tobytes(signers: &Vec<frost_secp256k1::signature::Signer>, indexsign: u32)->[u8;700] 
{
// Each signer Party is made up of 70 bytes . Total 10 signers are used in 7/11 configuration
//Only ten signers are available as one party takes role of signature aggreagator . 
    // Custom bytes structure of Signer Party
    //0..33 first share 
    //33..66 second share 
    //66.70 index
    // loop through 

 
    let mut index=indexsign;
    let mut returnbytes: [u8;700]=[0;700];
    let mut count =indexsign;
    let mut start_bytes=0;
    let mut end_bytes=33;
    while count<10
    {
        let bytes1=signers[index as usize].published_commitment_share.0.to_bytes();
        let bytes2=signers[index as usize].published_commitment_share.1.to_bytes();
        returnbytes[start_bytes..end_bytes].copy_from_slice(&bytes1);
        start_bytes=end_bytes;
        end_bytes=end_bytes+33;
        returnbytes[start_bytes..end_bytes].copy_from_slice(&bytes2);
        start_bytes=end_bytes;
        end_bytes=end_bytes+4;
        returnbytes[start_bytes..end_bytes].copy_from_slice(&signers[index as usize].participant_index.to_be_bytes());
        start_bytes=end_bytes;
        end_bytes=end_bytes+33;
        count=count+1;
        index=index+1;

    }
       returnbytes    
      
    

}
fn signer_bytes_to_ten_vector( signerbytes:[u8;700] )-> Vec<frost_secp256k1::signature::Signer>
{
   // Custom bytes 
    //0..33 first share 
    //33..66 second share 
    //66.70 index
    // loop through 
   // Convert 70 bytes back to 2 affine points and index and use signer constructor to create signer again 

    let mut signervector :Vec<frost_secp256k1::signature::Signer>=vec![];
    let mut indexbytes:[u8;4]=[0;4];
    let mut count=0;
    let mut startbytes=0;
    let mut endbytes=33;
    while count <10
    {
       
        let mut affinebytes:[u8;33]=[0;33];
        affinebytes.copy_from_slice(&signerbytes[startbytes..endbytes]);
       
        let  genarrya=GenericArray::from_slice(affinebytes.as_ref());
        let affine1 :AffinePoint=AffinePoint::from_bytes(&genarrya).unwrap();   
        startbytes=endbytes;
        endbytes=endbytes+33;
     let mut affinebytes:[u8;33]=[0;33];     
     affinebytes.copy_from_slice(&signerbytes[startbytes..endbytes]);
     let  genarrya=GenericArray::from_slice(affinebytes.as_ref());
     let affine2 :AffinePoint=AffinePoint::from_bytes(&genarrya).unwrap();
     startbytes=endbytes;
     endbytes=endbytes+4;
     indexbytes.copy_from_slice(&signerbytes[startbytes..endbytes]);
     let indexcommit:u32=u32::from_be_bytes(indexbytes);
     let  signer1:frost_secp256k1::signature::Signer=Signer { participant_index: indexcommit, published_commitment_share: (affine1,affine2) };        
    signervector.push(signer1);
    startbytes=endbytes;
    endbytes=endbytes+33;
    count=count+1;

    }

    return signervector;
   

}



