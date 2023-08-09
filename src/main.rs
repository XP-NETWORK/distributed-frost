//use core::slice::SlicePattern;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use frost_secp256k1::DistributedKeyGeneration;
use frost_secp256k1::GroupKey;
use frost_secp256k1::IndividualSecretKey;
use frost_secp256k1::keygen;
use frost_secp256k1::keygen::SecretShare;
use frost_secp256k1::precomputation::CommitmentShare;
use k256::AffinePoint;
use k256::PublicKey;
use frost_secp256k1;
use frost_secp256k1::Participant;
//use frost_secp256k1::Participant::*;
use frost_secp256k1::Parameters;
use k256::Scalar;
use k256::Secp256k1;
use k256::SecretKey;
//use k256::elliptic_curve::Scalar;
use k256::elliptic_curve::ScalarArithmetic;
use k256::elliptic_curve::group::GroupEncoding;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::io::Write;
use serde;
use std::convert::TryInto;

use k256::ecdsa::Signature;
use k256::ecdsa::signature::Signer;

use core::convert::TryFrom;
use generic_array::GenericArray;
use generic_array::typenum::Unsigned;

fn lines_from_file(filename: &str) -> Vec<String> {
    let mut file = match File::open(filename) {
        Ok(file) => file,
        Err(_) => panic!("no such file"),
    };
    let mut file_contents = String::new();
    file.read_to_string(&mut file_contents)
        .ok()
        .expect("failed to read!");
    let lines: Vec<String> = file_contents
        .split("\n")
        .map(|s: &str| s.to_string())
        .collect();
    lines
}

fn convert_secret_to_bytes(secretvector: &Vec<SecretShare>)->[u8;440]
{
    let total=secretvector.len();
    let mut count=0;
    let mut secretbytes: [u8;440]=[0;440];
    let mut startindex=0;
    let mut endindex=0;
    while count<total
    {   
        let writebytes: Vec<u8>=bincode::serialize(&secretvector[count]).unwrap();
        
        let size: usize =writebytes.len();
        endindex=endindex+size;
        secretbytes[startindex..endindex].copy_from_slice(writebytes.as_slice());

        //bytes_for_r.copy_from_slice(&party_bytes[0..40]);
        
        println!("{}",size);

        count=count+1;
        startindex=endindex;

    }
    

    secretbytes

}
fn convert_bytes_to_secret(secretbytes:[u8;440] )->Vec<SecretShare>
{
    
    let mut secret_vector_from_bytes :Vec<SecretShare>=vec![];
    
     let mut startindex=0;
     let mut endindex=44;
     let mut total=11;
     let mut count=1;
     while count<total
    {   
        let mut bytesvalues: [u8;44]=[0;44];
        bytesvalues.copy_from_slice(&secretbytes[startindex..endindex]);
        let clone_secret_share: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&bytesvalues);
        secret_vector_from_bytes.push(clone_secret_share.unwrap());
                count=count+1;
         startindex=endindex;
         endindex=endindex+44;

    }
    
    secret_vector_from_bytes

}

//
//Line 150 for Main 
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
    //threholdvalue=7;// hard coding 7/11 validators
   // totalvalue=11; // hard coding 11 validators
    //id=name.trim().parse().unwrap();
    //taking inout of id



    // create Directory for file 
    let mut pathfile = String::from("/opt/datafrost/") + lines[0].to_string().trim() + "/";
    let _res=fs::create_dir(&pathfile);
    let mut publickeytofile = pathfile + "public" + &lines[0].to_string() + ".txt";
    fs::remove_file(&publickeytofile).expect("could not remove file");
    let mut data_file = File::create(publickeytofile).expect("creation failed");

    // Create Participant using parameters
    let params = Parameters { n: totalvalue, t:threholdvalue };
    let   (mut party, _partycoeffs) = Participant::new(&params, id);
    //Convert Public key to bytes
        let public_bytes =party.public_key().unwrap().to_bytes();
        let _file_write_result=data_file.write_all(&public_bytes);
        let mut public_key_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/public" + id.to_string().trim()+ ".txt";
        let mut file = match File::open(&public_key_filepath) {
            Ok(file) => file,
            Err(_) => panic!("no such file"),
        };
        //let mut bufferfile :[u8;65]=[0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4];
        let mut bufferfile: [u8;33]=[0;33];
          let _ = file.read_exact( &mut bufferfile);
         // let xyz3: Result<k256::elliptic_curve::PublicKey<k256::Secp256k1>, k256::elliptic_curve::Error>= PublicKey::from_sec1_bytes(&bufferfile)   ;
          //let mut blab=Participant::new(&params, id);

          let testing3bytes=false;

          if testing3bytes==true{
      // write code for 3 party testing
      
      let bytes_committed=convert_party3_to_bytes(&id, &party, &party.proof_of_secret_key);
      let partyconv=convert_bytes_to_party3(&bytes_committed);
      party.clone_from(&partyconv);
      //party.clone_from();
      //println!("original Party{:?}",party);
      //println!("Converted Party {:?}",partyfrmbyes);


        
      let mut participantvectorpath = String::from("/opt/datafrost/") +&lines[0].to_string()+ "/participantvector" + &lines[0].to_string() + ".txt";
     
      println!("Verify the Participantvectorbinary file at {}",&participantvectorpath);
      fs::remove_file(&participantvectorpath).expect("could not remove file");
      let mut data_filecommit = File::create(&participantvectorpath).expect("creation failed"); // writing 
      let result_file_write=data_filecommit.write_all(&bytes_committed);
      
      
      let _=std::io::stdin().read_line(&mut name);
      let mut  other_Party_vectors: Vec<Participant>= vec!();
      let mut counter_party=1;
     // other_Party_vectors.clear();
      while (counter_party<4)
      {
          
          if counter_party==id
          {
              println!("Do nothing for self file creation");
          }
          else 
                          
          {
              let  path_to_read_party_vector = String::from("/opt/datafrost/") +&counter_party.to_string()+ "/participantvector" + &counter_party.to_string() + ".txt";
              let mut file = match File::open(&path_to_read_party_vector) {
                  Ok(file) => file,
                  Err(_) => panic!("no such file"),
              };
              println!("{:?}",path_to_read_party_vector);
              let mut result_bytes_from_file:[u8;150]=[0;150];
              let result_read=file.read_exact(&mut result_bytes_from_file);

              //if result_read.is_ok()
              {
                  let mut party_input=convert_bytes_to_party3(&result_bytes_from_file);
                  
                  //println!("Value of Party vector {}",12-counter_party);

                  if party_input.index==party.index
                  {
                      println!("Dont push self key {} to Other party vector ",party_input.index)
                  }
                  else
                  {
                      println!("             ",);
                      println!("{:?}",party_input);
                       other_Party_vectors.push(party_input);
                  
                  
                  }
                
              }

              
          }
          counter_party=counter_party+1;

      }
      println!("{}",other_Party_vectors.len());
      println!("{}",counter_party);
      println!("waiting for DKG round 1");
      std::io::stdin().read_line(&mut name);


     // Go For DKG Part-1

      //DKG first Part  Round One 
      
      
      let mut partystate=DistributedKeyGeneration::<_>::new(&params,&id,&_partycoeffs,&mut other_Party_vectors).or(Err(())).unwrap();

      let mut partyone_secrets: &Vec<SecretShare>=partystate.their_secret_shares().unwrap();

      // println!("Secrets Vector Done for Id {} ",id);
      let total_secret_shares=partyone_secrets.len();
       println!("{:?}",partyone_secrets);
       println!("{:?}",partyone_secrets.len());
     
       let fullparty: [u8; 88]=convert_secret_to_3bytes(partyone_secrets);

       let mut secret_share_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/party_secrets" + id.to_string().trim()+ ".txt";
       fs::remove_file(&secret_share_filepath).expect("could not remove file");
       let mut secret_file = File::create(&secret_share_filepath).expect("creation failed");
       let result=secret_file.write_all(&fullparty);

       println!("Checking all files are written with party scecrets");
       std::io::stdin().read_line(&mut name);
       

          // Start loop for retreiving secrets from all personnel
          // read all secret file vectors from other parties and select all secret shares with own id 
          let mut other_party_secret_shares: Vec<SecretShare>=vec!();
          let mut  file_nos=1;
          while file_nos<4
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

          let mut secret_bytes : [u8;88]=[0;88];
          file.read_exact(&mut secret_bytes);
          let mut shared_vector=convert_bytes_to_3secret(secret_bytes);
          // find shares belonging to self from file 
          let mut vari_count=0;
          while (vari_count<shared_vector.len()+1)
          {
              if shared_vector[vari_count].index==id
              {println!("going through this file for self vector {}",secret_share_filepath);
                  other_party_secret_shares.push(shared_vector[vari_count].clone());
                  
                  break;
              }
              vari_count=vari_count+1;

          }


              } // else 
              file_nos=file_nos+1;
              
          } // while reading all files

         
          let  partystate2: DistributedKeyGeneration<keygen::RoundOne>=partystate.clone();
      
          let  partystaternd2: Result<DistributedKeyGeneration<keygen::RoundTwo>, ()> = partystate2.clone().to_round_two( other_party_secret_shares);
          
          let partystaternd2: DistributedKeyGeneration<keygen::RoundTwo>=partystaternd2.unwrap();
  
          let mut Partyfinale=partystaternd2.finish(&party.public_key().unwrap()).unwrap();
          
          //let mut partysecretkey=blabblabbalb.as_mut().unwrap().1;
          println!("Groupkey");
          println!("{:?}",Partyfinale.0);
           
  
           println!("Secret key full ");
            println!("{:?}",&mut Partyfinale.1);
          // println!("{:?}",&mut blabblabbalb.1);
           println!("Public key from Private key ");
           println!("{:?}",&mut Partyfinale.1.to_public());
 










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
              
          }
          else {




        let bytes_committed=convert_party_to_bytes(&id, &party, &party.proof_of_secret_key);

        
         let mut participantvectorpath = String::from("/opt/datafrost/") +&lines[0].to_string()+ "/participantvector" + &lines[0].to_string() + ".txt";
        
         println!("Verify the Participantvectorbinary file at {}",&participantvectorpath);
//         std::io::stdin().read_line(&mut name);
            fs::remove_file(&participantvectorpath).expect("could not remove file");
         let mut data_filecommit = File::create(&participantvectorpath).expect("creation failed"); // writing 
         let result_file_write=data_filecommit.write_all(&bytes_committed);
        
        // Convert original party to 32 bytes party with z value zero 
         let partyconv=convert_bytes_to_party(&bytes_committed);
         party.clone_from(&partyconv);
    
    
    
    
    
        
    
    // Create all files for computation if filler = ture
        let mut filler =false;
        let mut file_nos=1;
       while file_nos<12 && filler== true
       {
           if file_nos==id
           {

           }
           else {
               
           
           let mut pathfile = String::from("/opt/datafrost/") + &file_nos.to_string().trim() + "/";
           let _res=fs::create_dir(&pathfile);
           let mut publickeytofile = pathfile + "public" + &file_nos.to_string() + ".txt";
           let mut data_file = File::create(publickeytofile).expect("creation failed");
       
           // Create Participant using parameters
           let params = Parameters { n: totalvalue, t:threholdvalue };
           let (party_to_write, _partycoeffs) = Participant::new(&params, file_nos);
           //Convert Public key to bytes
               let public_bytes =party_to_write.public_key().unwrap().to_bytes();
               let _file_write_result=data_file.write_all(&public_bytes);
               let mut public_key_filepath = String::from("/opt/datafrost/")+ file_nos.to_string().trim()  + "/public" + file_nos.to_string().trim()+ ".txt";
               let mut file = match File::open(&public_key_filepath) {
                   Ok(file) => file,
                   Err(_) => panic!("no such file"),
               };
               let bytes_committed=convert_party_to_bytes(&file_nos, &party_to_write, &party_to_write.proof_of_secret_key);

                    
                let mut participantvectorpath = String::from("/opt/datafrost/") +&file_nos.to_string()+ "/participantvector" + &file_nos.to_string() + ".txt";
               
                println!("Verify the Participantvectorbinary file at {}",&participantvectorpath);
                //std::io::stdin().read_line(&mut name);
             
                let mut data_filecommit = File::create(&participantvectorpath).expect("creation failed"); // writing 
                let result_file_write=data_filecommit.write_all(&bytes_committed);

           }
           file_nos=file_nos+1;
       }// Files Creation Loop ends


        //let partyglobal=convert_bytes_to_party(&bytes_committed);
                 std::io::stdin().read_line(&mut name);
        let mut  other_Party_vectors: Vec<Participant>= vec!();
        let mut counter_party=1;
       // other_Party_vectors.clear();
        while (counter_party<12)
        {
            
            if counter_party==id
            {
                println!("Do nothing for self file creation");
            }
            else 
                            
            {
                let  path_to_read_party_vector = String::from("/opt/datafrost/") +&counter_party.to_string()+ "/participantvector" + &counter_party.to_string() + ".txt";
                let mut file = match File::open(&path_to_read_party_vector) {
                    Ok(file) => file,
                    Err(_) => panic!("no such file"),
                };
                println!("{:?}",path_to_read_party_vector);
                let mut result_bytes_from_file:[u8;315]=[0;315];
                let result_read=file.read_exact(&mut result_bytes_from_file);

                //if result_read.is_ok()
                {
                    let mut party_input=convert_bytes_to_party(&result_bytes_from_file);
                    
                    //println!("Value of Party vector {}",12-counter_party);

                    if party_input.index==party.index
                    {
                        println!("Dont push self key {} to Other party vector ",party_input.index)
                    }
                    else
                    {
                        println!("             ",);
                        println!("{:?}",party_input);
                         other_Party_vectors.push(party_input);
                    
                    
                    }
                  
                }

                
            }
            counter_party=counter_party+1;

        }
        println!("{}",other_Party_vectors.len());
        println!("{}",counter_party);
        std::io::stdin().read_line(&mut name);

       // Go For DKG Part-1

        //DKG first Part  Round One 
        // with mulit parties
        
        
        let mut partystate=DistributedKeyGeneration::<_>::new(&params,&id,&_partycoeffs,&mut other_Party_vectors).or(Err(())).unwrap();

        let mut partyone_secrets: &Vec<SecretShare>=partystate.their_secret_shares().unwrap();

        // println!("Secrets Vector Done for Id {} ",id);
        let total_secret_shares=partyone_secrets.len();
         println!("{:?}",partyone_secrets);
         println!("{:?}",partyone_secrets.len());

     
        
        //Write own Share to file 
        
        let fullparty=convert_secret_to_bytes(partyone_secrets);

         let mut secret_share_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/party_secrets" + id.to_string().trim()+ ".txt";
         fs::remove_file(&secret_share_filepath).expect("could not remove file");
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
            {println!("going through this file {}",secret_share_filepath);
                if shared_vector[vari_count].index==id
                {
                    other_party_secret_shares.push(shared_vector[vari_count].clone());
                    
                    break;
                }
                vari_count=vari_count+1;

            }


                } // else 
                file_nos=file_nos+1;
                
            } // while reading all files

           
            let  partystate2: DistributedKeyGeneration<keygen::RoundOne>=partystate.clone();
        
            let  partystaternd2: Result<DistributedKeyGeneration<keygen::RoundTwo>, ()> = partystate2.clone().to_round_two( other_party_secret_shares);
            
            let partystaternd2: DistributedKeyGeneration<keygen::RoundTwo>=partystaternd2.unwrap();
    
            let mut Partyfinale=partystaternd2.finish(&party.public_key().unwrap()).unwrap();
            
            //let mut partysecretkey=blabblabbalb.as_mut().unwrap().1;
            println!("Groupkey");
            println!("{:?}",Partyfinale.0);
             
    
             println!("Secret key full ");
              println!("{:?}",&mut Partyfinale.1);
            // println!("{:?}",&mut blabblabbalb.1);
             println!("Public key from Private key ");
             println!("{:?}",&mut Partyfinale.1.to_public());

     
        


}
fn convert_party_to_bytes(index: &u32, commitments_party: &frost_secp256k1::Participant,zkp:&frost_secp256k1::nizk::NizkOfSecretKey) -> [u8;315]{



    let mut resultbytes:[u8;315]=[0;315];
    let mut resultdummy: [u8;40]=[0;40];
    let rbytes=bincode::serialize(&zkp.r).unwrap();
    let split=rbytes.split_at(40);
    resultbytes[0..40].clone_from_slice(&split.0);
    let sbytes=bincode::serialize(&zkp.s).unwrap();
    let split=sbytes.split_at(40);
    resultbytes[40..80].clone_from_slice(&split.0);
    /*
    let generic_array: [u32; 4] = [1, 2, 3, 4];
    let fixed_size_array: [u8; 16] = unsafe { std::mem::transmute(generic_array) };
    
     */
    //loop through 7 Commitments of 33 bytes 
    let mut commit_count=0;
    let mut startin_byte_index=80;
    while commit_count<7
    {   let ending_index=startin_byte_index+33;
        let commitmentbytes=commitments_party.commitments[commit_count].to_bytes();
        let commit_split=commitmentbytes.split_at(33);
        resultbytes[startin_byte_index..ending_index].clone_from_slice(commit_split.0);
        startin_byte_index=ending_index;
        commit_count=commit_count+1;

    }
    
    resultbytes[startin_byte_index..315].copy_from_slice(index.to_be_bytes().as_slice());
    

      



    resultbytes
}
pub struct ZKPSecretKey {
    /// The scalar portion of the Schnorr signature encoding the context.
    pub s: Scalar,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    pub r: Scalar,
}


fn convert_bytes_to_party(party_bytes: &[u8;315]) -> (Participant)
{
    let mut commit_vector:Vec<k256::ProjectivePoint>=vec!();
    
    let mut bytes_sequence :[u8;4]=[0,1,2,3];
    bytes_sequence.clone_from_slice(&party_bytes[311..315]);
    
    //let value_index=indexconvert as u32
    let index_u32_integer: u32 = ((bytes_sequence[0] as u32) << 24)
                    | ((bytes_sequence[1] as u32) << 16)
                    | ((bytes_sequence[2] as u32) << 8)
                    | (bytes_sequence[3] as u32);;
   
    let mut bytes_for_r: [u8;40]=[0;40];
    let mut bytes_for_s:[u8;40]=[0;40];
    bytes_for_r.copy_from_slice(&party_bytes[0..40]);
    bytes_for_s.copy_from_slice(&party_bytes[40..80]);
   
    let mut commit=0;
    let mut start_bytes=80;
    while(commit<7)
    {
        let endvalue=start_bytes+33;
        let mut bytescommit:[u8;33]=[0;33];
        
        
       
        bytescommit.copy_from_slice(&party_bytes[start_bytes..endvalue]);
        let mut genarray=GenericArray::from_slice(bytescommit.as_ref());
       
        let mut byte_projective=k256::ProjectivePoint::from_bytes(&genarray).unwrap(); 
               
        commit_vector.push(byte_projective);

        start_bytes=endvalue;
        commit=commit+1;

    }
    let mut poof :ZKPSecretKey;
    




    
    let  skey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(bytes_for_s.as_ref());
    let  rkey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(bytes_for_r.as_ref());
    
    let mut zkpfull :frost_secp256k1::nizk::NizkOfSecretKey= frost_secp256k1::nizk::NizkOfSecretKey { s: skey.unwrap(), r: rkey.unwrap() };
    


    let mut party_convert: Participant=Participant { index: index_u32_integer , commitments: commit_vector, proof_of_secret_key: zkpfull };


party_convert
}


    fn convert_party_to_bytes2(index: &u32, commitments_party: &frost_secp256k1::Participant,zkp:&frost_secp256k1::nizk::NizkOfSecretKey) -> [u8;299]{



        let mut resultbytes:[u8;299]=[0;299];
        // Structure of bytes
        // ZKP R scaler 32 bytes
        // ZKP S scaler 32 bytes
        // 7 Commitments shares 33 bytes=231
        // index u32 ->u8 = 4 bytes
        // Total=32+32+33+33+33+33+33+33+33+4=299 
        let mut resultdummy: [u8;32]=[0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,1,2];
        
        let zkpbytes=zkp.r.to_bytes();
        let zkpsplitter=zkpbytes.split_at(32);
        resultdummy.clone_from_slice(zkpsplitter.0);
        resultbytes[0..32].clone_from_slice(zkpsplitter.0);
        //resultbytes[0..32]=resultdummy;
        //S bytes 
        let zkpbytes: k256::elliptic_curve::generic_array::GenericArray<u8, _>=zkp.s.to_bytes();
        let zkpsplitter=zkpbytes.split_at(32);
        resultdummy.clone_from_slice(zkpsplitter.0);
        resultbytes[32..64].clone_from_slice(zkpsplitter.0);
        let rbytes=bincode::serialize(&zkp.r).unwrap();
        resultbytes[0..32].clone_from_slice(&rbytes.as_ref());
        let sbytes=bincode::serialize(&zkp.s).unwrap();
        resultbytes[32..64].clone_from_slice(&sbytes.as_ref());
        /*
        let generic_array: [u32; 4] = [1, 2, 3, 4];
        let fixed_size_array: [u8; 16] = unsafe { std::mem::transmute(generic_array) };
        
         */
        //loop through 7 Commitments of 33 bytes 
        let mut commit_count=0;
        let mut startin_byte_index=64;
        while commit_count<7
        {   let ending_index=startin_byte_index+33;
            let commitmentbytes=commitments_party.commitments[commit_count].to_bytes();
            let commit_split=commitmentbytes.split_at(33);
            resultbytes[startin_byte_index..ending_index].clone_from_slice(commit_split.0);
            startin_byte_index=ending_index;
            commit_count=commit_count+1;
    
        }
        
        resultbytes[startin_byte_index..299].copy_from_slice(index.to_be_bytes().as_slice());
        
    
          
    
    
    
        resultbytes
    }

    fn convert_party3_to_bytes(index: &u32, commitments_party: &frost_secp256k1::Participant,zkp:&frost_secp256k1::nizk::NizkOfSecretKey) -> [u8;150]{



        let mut resultbytes:[u8;150]=[0;150];
        let mut resultdummy: [u8;40]=[0;40];
        println!("{}",zkp.r.to_bytes().len());
        let rbytes=bincode::serialize(&zkp.r).unwrap();
//        let  rkey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(&rbytes.as_ref());
        
      //  println!("Party Rbytes for {} {:?}",index,rbytes); // for verification of Party R
      //  println!("Party R for {} {:?} after deserial",index,rkey.unwrap()); // for verification of Party R
        let split=rbytes.split_at(40);
        resultbytes[0..40].clone_from_slice(&split.0);
        //println!("Party S for {} {:?}",index,zkp.s); // for verification of Party S
        let sbytes=bincode::serialize(&zkp.s).unwrap();
        let split=sbytes.split_at(40);
        resultbytes[40..80].clone_from_slice(&split.0);
        let  skey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(&sbytes.as_ref());
        
       // println!("Party S for {} {:?}",index,zkp.s); // for verification of Party R
       // println!("Party S for {}  after deserial{:?}",index,skey.unwrap()); // for verification of Party R
        
        //loop through 2 Commitments of 33 bytes 
        let mut commit_count=0;
        let mut startin_byte_index=80;
        while commit_count<2
        {   let ending_index=startin_byte_index+33;
            let commitmentbytes=commitments_party.commitments[commit_count].to_bytes();
            let commit_split=commitmentbytes.split_at(33);
            resultbytes[startin_byte_index..ending_index].clone_from_slice(commit_split.0);
            startin_byte_index=ending_index;
            commit_count=commit_count+1;
    
        }
        
        resultbytes[startin_byte_index..150].copy_from_slice(index.to_be_bytes().as_slice());
        
          
        
    
    
        resultbytes
    }

    fn convert_bytes_to_party3(party_bytes: &[u8;150]) -> (Participant)
    {
        let mut commit_vector:Vec<k256::ProjectivePoint>=vec!();
        
        let mut bytes_sequence :[u8;4]=[0,0,0,0];
        bytes_sequence.clone_from_slice(&party_bytes[146..150]);
        
        //let value_index=indexconvert as u32
        let index_u32_integer: u32 = ((bytes_sequence[0] as u32) << 24)
                        | ((bytes_sequence[1] as u32) << 16)
                        | ((bytes_sequence[2] as u32) << 8)
                        | (bytes_sequence[3] as u32);;
       
        let mut bytes_for_r: [u8;40]=[0;40];
        let mut bytes_for_s:[u8;40]=[0;40];
        bytes_for_r.copy_from_slice(&party_bytes[0..40]);
        bytes_for_s.copy_from_slice(&party_bytes[40..80]);
        // create scaler from deserializing bytes
        
        let  skey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(bytes_for_s.as_ref());
        let  rkey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(bytes_for_r.as_ref());
        
        // prepare zk proof from scaler values
        //let value =frost_secp256k1::nizk::NizkOfSecretKey{s,r}
        let  zkpfull :frost_secp256k1::nizk::NizkOfSecretKey= frost_secp256k1::nizk::NizkOfSecretKey { s: skey.unwrap(), r: rkey.unwrap() };
       
        let mut commit=0;
        let mut start_bytes=80;
        while(commit<2)
        {
            let endvalue=start_bytes+33;
            let mut bytescommit:[u8;33]=[0;33];                                   
            bytescommit.copy_from_slice(&party_bytes[start_bytes..endvalue]);
            let mut genarray=GenericArray::from_slice(bytescommit.as_ref());
            let mut byte_projective=k256::ProjectivePoint::from_bytes(&genarray).unwrap();                   
            commit_vector.push(byte_projective);
            start_bytes=endvalue;
            commit=commit+1;
    
        }
        //let mut poof :ZKPSecretKey;
        
        
        
    
        let  party_convert: Participant=Participant { index: index_u32_integer , commitments: commit_vector, proof_of_secret_key: zkpfull };
    
    
    party_convert
    }    

    fn convert_secret_to_3bytes(secretvector: &Vec<SecretShare>)->[u8;88]
{
    let total=secretvector.len();
    let mut count=0;
    let mut secretbytes: [u8;88]=[0;88];
    let mut startindex=0;
    let mut endindex=0;
    while count<total
    {   
        let writebytes: Vec<u8>=bincode::serialize(&secretvector[count]).unwrap();
        
        let size: usize =writebytes.len();
        endindex=endindex+size;
        secretbytes[startindex..endindex].copy_from_slice(writebytes.as_slice());

        //bytes_for_r.copy_from_slice(&party_bytes[0..40]);
        
        println!("{}",size);

        count=count+1;
        startindex=endindex;

    }
    

    secretbytes

}
fn convert_bytes_to_3secret(secretbytes:[u8;88] )->Vec<SecretShare>
{
    
    let mut secret_vector_from_bytes :Vec<SecretShare>=vec![];
    
     let mut startindex=0;
     let mut endindex=44;
     let mut total=3;
     let mut count=1;
     while count<total
    {   
        let mut bytesvalues: [u8;44]=[0;44];
        bytesvalues.copy_from_slice(&secretbytes[startindex..endindex]);
        let clone_secret_share: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&bytesvalues);
        secret_vector_from_bytes.push(clone_secret_share.unwrap());
                count=count+1;
         startindex=endindex;
         endindex=endindex+44;

    }
    
    secret_vector_from_bytes

}
