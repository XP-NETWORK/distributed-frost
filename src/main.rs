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
//use k256::Scalar;
//use k256::SecretKey;
//use k256::{Scalar, SecretKey, SecretKeyBytes};



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


//Line 50 for Main 
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
       
    println!("id ={} , thresh={},total={}", id.to_string(), threholdvalue.to_string(), totalvalue.to_string());
    threholdvalue=7;// hard coding 7/11 validators
    totalvalue=11; // hard coding 11 validators
    id=name.trim().parse().unwrap();
    //taking inout of id


    // create Directory for file 
    let mut pathfile = String::from("/opt/datafrost/") + lines[0].to_string().trim() + "/";
    let _res=fs::create_dir(&pathfile);
    let mut publickeytofile = pathfile + "public" + &lines[0].to_string() + ".txt";
    let mut data_file = File::create(publickeytofile).expect("creation failed");

    // Create Participant using parameters
    let params = Parameters { n: totalvalue, t:threholdvalue };
    let (party, _partycoeffs) = Participant::new(&params, id);
    //Convert Public key to bytes
        let public_bytes =party.public_key().unwrap().to_bytes();
        let _file_write_result=data_file.write_all(&public_bytes);
        let mut public_key_filepath = String::from("/opt/datafrost/")+ id.to_string().trim()  + "/public" + id.to_string().trim()+ ".txt";
        let mut file = match File::open(&public_key_filepath) {
            Ok(file) => file,
            Err(_) => panic!("no such file"),
        };
        //let mut bufferfile :[u8;65]=[0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4];
        let mut bufferfile: [u8;33]=[0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,1,2,3];
          let _ = file.read_exact( &mut bufferfile);
          let xyz3: Result<k256::elliptic_curve::PublicKey<k256::Secp256k1>, k256::elliptic_curve::Error>= PublicKey::from_sec1_bytes(&bufferfile)   ;
          let mut blab=Participant::new(&params, id);
         // println!("number of commmimments{}",party.commitments.len());
        //  println!("{}",party.commitments[0].to_bytes().len());
         // println!("{}",party.commitments[7].to_bytes().len());

        //   blab.0.commitments.clear();
        //   //blab.0.commitments.push(value);
        // println!("rbytes {:?},",   blab.0.proof_of_secret_key.r.to_bytes());
        // println!("sbytes {:?}," ,  blab.0.proof_of_secret_key.s.to_bytes());
        // println!("rbytes {:?},",   blab.0.proof_of_secret_key.r.to_bytes().len());
        // println!("sbytes {:?}," ,  blab.0.proof_of_secret_key.s.to_bytes().len());

        let bytes_committed=convert_party_to_bytes(&id, &party, &party.proof_of_secret_key);

        // println!("Party bytes");
        // println!("{:?}",bytes_committed);
        // let sample: Vec<u8>=bincode::serialize(&party.proof_of_secret_key.r).unwrap();
        // println!("{:?}",sample);
        // println!("{:?}",sample.capacity());
        // let scl: Result<Scalar, Box<bincode::ErrorKind>>=bincode::deserialize(&sample.as_ref());
        
        // println!("{:?}",scl.unwrap());
        //  println!("{:?}",party.proof_of_secret_key.r);
        //  println!("{:?}",party.proof_of_secret_key.s);
        //  println!("{:?}",party.commitments[0]);
        //  println!("{:?}",party.commitments[1]);
        //  println!("{:?}",party.commitments[2]);
        //  println!("{:?}",party.commitments[3]);
        //  println!("{:?}",party.commitments[4]);
        //  println!("{:?}",party.commitments[5]);
        //  println!("{:?}",party.commitments[6]);

         let mut participantvectorpath = String::from("/opt/datafrost/") +&lines[0].to_string()+ "/participantvector" + &lines[0].to_string() + ".txt";

         println!("Verify the Participantvectorbinary file at {}",&participantvectorpath);
         std::io::stdin().read_line(&mut name);
      
         let mut data_filecommit = File::create(&participantvectorpath).expect("creation failed"); // writing 
         let result_file_write=data_filecommit.write_all(&bytes_committed);
// let Parties :Participant=Participant { index: (), commitments: (), proof_of_secret_key: () }
// Parties.clone_from(source);
        
                //let proofofkey=frost_secp256k1::nizk::NizkOfSecretKey(s,r);
        // let mut bytes_sequence :[u8;4]=[0,1  ,2,3];
        // bytes_sequence.clone_from_slice(&bytes_committed[295..299]);
        
        // //let value_index=indexconvert as u32
        // let u32_integer: u32 = ((bytes_sequence[0] as u32) << 24)
        //                 | ((bytes_sequence[1] as u32) << 16)
        //                 | ((bytes_sequence[2] as u32) << 8)
        //                 | (bytes_sequence[3] as u32);;
        // println!("{:?}",u32_integer);
        // println!("Index from u8 to u32 bytes");
        // let mut bytes_for_r: [u8;32]=[0;32];
        // bytes_for_r.copy_from_slice(&bytes_committed[0..32]);
        // println!("{:?}",bytes_for_r);
        // println!("from original value");
        // println!("{:?}",party.proof_of_secret_key.r.to_bytes());
        // let mut commit=0;
        // let mut start_bytes=64;
        // while(commit<7)
        // {
        //     let endvalue=start_bytes+33;
        //     let mut bytescommit:[u8;33]=[0;33];
        //     bytescommit.copy_from_slice(&bytes_committed[start_bytes..endvalue]);
        //     println!("bytes from functon");
        //     println!("{:?}",bytescommit);
        //     println!("bytes from commitment vector {}",commit );
        //     println!("{:?}",party.commitments[commit].to_bytes());
        //     start_bytes=endvalue;
        //     commit=commit+1;



        // }
        let partyglobal=convert_bytes_to_party(&bytes_committed);
        
        let mut  other_Party_vectors: Vec<Participant>= vec!();
        let mut counter_party=1;
       // other_Party_vectors.clear();
        while (counter_party<12)
        {
            
            //if counter_party!=id
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

                    if party_input.index!=party.index
                    {
                        println!("{:?}",party_input);
                    other_Party_vectors.push(party_input);
                    
                    println!("             ",);
                    }
                  
                }

                
            }
            counter_party=counter_party+1;
        }
        println!("{}",other_Party_vectors.len());
        println!("{}",counter_party);
        std::io::stdin().read_line(&mut name);

        counter_party=0;
        // printing 
        // while counter_party<10
        
        // {
        //     println!("             ",);
        //     println!("Value of Party vector {}",counter_party);
        //     println!("             {}",counter_party);
        //     println!("{:?}",other_Party_vectors[counter_party as usize]);
        //     counter_party=counter_party+1;

        // }
        
        
        // println!("{:?}",partyglobal.index);
        // println!("{:?}",partyglobal.proof_of_secret_key.r);
        //  println!("{:?}",partyglobal.proof_of_secret_key.s);
        //  println!("{:?}",partyglobal.commitments[0]);
        //  println!("{:?}",partyglobal.commitments[1]);
        //  println!("{:?}",partyglobal.commitments[2]);
        //  println!("{:?}",partyglobal.commitments[3]);
        //  println!("{:?}",partyglobal.commitments[4]);
        //  println!("{:?}",partyglobal.commitments[5]);
        //  println!("{:?}",partyglobal.commitments[6]);

       // party.commitments
        //println!("id{}",id.to_be_bytes().len());
        //   blab.0.proof_of_secret_key.s.to_bytes();
          // Participant File 
        //   let mut p1_participant=bincode::serialize(&party.commitments).unwrap();
        // println!("Participant bytes");sample.len()
        // println!("{:?}", p1_participant);
        // println!("Participant bytes lenth");
        // println!("{:?}", p1_participant.len());
        // let mut publickeytofile2 = String::from("/opt/datafrost/") + "public" + &lines[0].to_string() + "commit.txt";
          


}
fn convert_party_to_bytes(index: &u32, commitments_party: &frost_secp256k1::Participant,zkp:&frost_secp256k1::nizk::NizkOfSecretKey) -> [u8;315]{



    let mut resultbytes:[u8;315]=[0;315];
    // Structure of bytes
    // ZKP R scaler 32 bytes //40bytes bincode
    // ZKP S scaler 32 bytes //40 bbytes bincode
    // 7 Commitments shares 33 bytes=231
    // index u32 ->u8 = 4 bytes
    // Total=32+32+33+33+33+33+33+33+33+4=299 
    //total=40+40++33+33+33+33+33+33+33+4=315
   // let mut resultdummy: [u8;40]=[0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,1,2,3,4,5,6,7,8,9,0];
    let mut resultdummy: [u8;40]=[0;40];
    //let zkpbytes=zkp.r.to_bytes();
    //let zkpsplitter=zkpbytes.split_at(32);
    //resultdummy.clone_from_slice(zkpsplitter.0);
    //resultbytes[0..32].clone_from_slice(zkpsplitter.0);
    //resultbytes[0..32]=resultdummy;
    //S bytes 
    //let zkpbytes: k256::elliptic_curve::generic_array::GenericArray<u8, _>=zkp.s.to_bytes();
    //let zkpsplitter=zkpbytes.split_at(32);
    //resultdummy.clone_from_slice(zkpsplitter.0);
    //resultbytes[32..64].clone_from_slice(zkpsplitter.0);
    let rbytes=bincode::serialize(&zkp.r).unwrap();
    //println!("{:?}",r);
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
        
        
        //genarray.clone_from(&party_bytes[start_bytes..endvalue]);
        
        //let mut byte_projective:k256::ProjectivePoint;

        bytescommit.copy_from_slice(&party_bytes[start_bytes..endvalue]);
        let mut genarray=GenericArray::from_slice(bytescommit.as_ref());
        //genarray.copy_from_slice(bytescommit.as_ref());
        
        //byte_p // zkpfull.r.add(&rkey);
    // zkpfull.s.add(&skey);rojective.clon
        let mut byte_projective=k256::ProjectivePoint::from_bytes(&genarray).unwrap(); 
        //let mut genarray: ge
        //let mut bytes_affine:AffinePoint=AffinePoint::from_bytes(&party_bytes[start_bytes..endvalue]).unwrap();
        
        commit_vector.push(byte_projective);

        start_bytes=endvalue;
        commit=commit+1;

    }
    let mut poof :ZKPSecretKey;
    
    
    let  skey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(bytes_for_s.as_ref());
    let  rkey: Result<Scalar, Box<bincode::ErrorKind>>  =bincode::deserialize(bytes_for_r.as_ref());
    //poof.r.clone_from(&rkey);
    //poof.s.clone_from(&skey);
    let mut zkpfull :frost_secp256k1::nizk::NizkOfSecretKey= frost_secp256k1::nizk::NizkOfSecretKey { s: skey.unwrap(), r: rkey.unwrap() };
    // zkpfull.r.add(&rkey);
    // zkpfull.s.add(&skey);


    //let mut alpha:dyn secp256k1::SecretKey;
    //Scalar::from(bytes_for_r.as_ref());
  



    // match SecretKey::from_bytes(&bytes) {
    //     Ok(secret_key) => {
    //         // The SecretKey is essentially a wrapper around Scalar
    //         let scalar: Scalar = secret_key.to_secret_scalar();
            
    //         // Do something with the scalar...
    //         println!("Scalar: {}", scalar);
    //     }
    //     Err(e) => {
    //         // Handle the error...
    //         eprintln!("Failed to create scalar: {}", e);
    //     }
    // }
    
//     let mut poof:ZKPSecretKey;
//     let mut scalar_result_r = Scalar::from_bytes_mod_order(&bytes_for_r);
//     let mut scalar_result_s = Scalar::from_bytes_mod_order(&bytes_for_s);
    
//     //poof.r.add(&Scalar::from(&bytes_for_r));
//     Secp256k1
//   let rscaler=SecretKey::from_be_bytes(&bytes_for_r);

    





    let mut party_convert: Participant=Participant { index: index_u32_integer , commitments: commit_vector, proof_of_secret_key: zkpfull };


party_convert
}
//     let x: Vec<k256::ProjectivePoint>;
//     //let ceoff: frost_secp256k1::keygen::Coefficients;
//     let index: u32;
//     let alpha :frost_secp256k1::nizk::NizkOfSecretKey;
//     return (x,alpha,index);
//     }
fn mainold()
{

      /*  
        
        
                
        
       
        let mut publickeytofile2 = String::from("/opt/datafrost/") + "public" + &lines[0].to_string() + "commit.txt";

        let mut data_filecommit = File::create(&publickeytofile2).expect("creation failed"); // writing 
        data_filecommit.write_all(&p1_participant);

        let mut file = match File::open(publickeytofile2) {
            Ok(file) => file,
            Err(_) => panic!("no such file"),
        };
        
        
        let mut bufstrng: [u8;131]=[0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,1,2,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,1,2,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,1,2,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,1,2,3,4,5];
        let xy=file.read_exact(&mut bufstrng);

        
        println!("compare{:?}",bufstrng);

        if p1_participant==bufstrng.as_ref()
        {
            println!("compare match between file and actual serializer");
            println!("131 ASCII from file {:?}",bufstrng);
            println!("131 ASCII  from memo {:?}",p1_participant);
        }
         
         let  p1frombytes: Result<Participant, Box<bincode::ErrorKind>>=bincode::deserialize::<Participant>(&bufstrng);
         match p1frombytes {
            Ok(val)=>{
                println!("ok {:?}",val);
            },
            Err(err)=>{
                println!("error {:?}",err);
            }
        }

       // Trying to serialize Affine point and trying to convert it back 
      

      let serialdata=bincode::serialize(&p1.commitments);
        let  p1frombytes: Result<AffinePoint, Box<bincode::ErrorKind>>=bincode::deserialize::<AffinePoint>(&serialdata.unwrap());
        match p1frombytes {
           Ok(val)=>{
               println!("ok {:?}",val);
           },
           Err(err)=>{
               println!("error {:?}",err);
           }
       }


       let mut partyfull =bincode::serialize(&p1).unwrap();

       
       let deserialpary:Participant=bincode::deserialize(&partyfull).unwrap();
       println!("{:?}",partyfull);
       println!("{:?}",deserialpary);
       let mut participantvectorpath = String::from("/opt/datafrost/") +&lines[0].to_string()+ "/participantvector" + &lines[0].to_string() + ".txt";

       println!("Verify the Participantvectorbinary file at {}",&participantvectorpath);
       std::io::stdin().read_line(&mut name);
    
       let mut data_filecommit = File::create(&participantvectorpath).expect("creation failed"); // writing 
       data_filecommit.write_all(&partyfull);


       let mut filedeserialized = match File::open(&participantvectorpath) {
           Ok(filedeserialized) => filedeserialized,
           Err(_) => panic!("no such file"),
       };
        // Read exact bytes for the Serialization vector 
        //
        

        
        // // initialize data with the length of file 
         let mut filederserial:[u8;199]=[199;199];


         let xyfile=filedeserialized.read_exact(&mut filederserial);
        
        // let partyicipantfile: Participant=bincode::deserialize(&filederserial).unwrap();
        // //if partyicipantfile
        // println!("{:?}",partyicipantfile.public_key());
        // let affinfromfile: AffinePoint=partyicipantfile.public_key().unwrap();

    // let resultproofkey=        partyicipantfile.proof_of_secret_key.verify(&id, &affinfromfile);
    //    if resultproofkey.is_ok()
    //    {
    //     println!("Proof of key successful from file for {:?}",affinfromfile);
    //    }
    //    println!("Party file from {}",&participantvectorpath);
    //    println!("{:?}",&partyicipantfile);
    //    println!("ORIGINAL file from ********************** ");
    //    println!("{:?}",&p1);
       
    //     println!("Verify the Participantvectorbinary files at {}",&participantvectorpath);
            let mut partyicipantfile1: Participant=bincode::deserialize(&filederserial).unwrap();
                let mut partyicipantfile2: Participant=bincode::deserialize(&filederserial).unwrap();
                let mut partyicipantfile3: Participant=bincode::deserialize(&filederserial).unwrap();

        std::io::stdin().read_line(&mut name);
        let mut countno=totalvalue;
         //let mut other_vectors :Vec<Participant>= vec![];
        //  let mut party1 : Participant;
        //  let mut party2: Participant;
        //  let mut party3:Participant;
        //  let mut party4 : Participant;
        //  //
         //let mut vectorcount: usize=0;
         let mut vectorcount: u32=0;

        while countno>0
        {
            if countno==id{

                println!("own file not being read");
                countno=countno-1;
            }
                       
            else {
                println!("In inner loop for file read ");
                let mut participantvectorpath = String::from("/opt/datafrost/") +&countno.to_string()+ "/participantvector" + &countno.to_string() + ".txt";
                let mut filedeserialized = match File::open(&participantvectorpath) {
                    Ok(filedeserialized) => filedeserialized,
                    Err(_) => panic!("no such file"),
                };
                 // initialize data with the length of file 
                let mut filederserial:[u8;199]=[0;199];
                println!("In inner loop for file read {} ",participantvectorpath);


                let xyfile=filedeserialized.read_exact(&mut filederserial);
                if xyfile.is_ok()
                {
                    println!(" key successful from file for {}",participantvectorpath);
                }
               // let partyicipantfile: Participant=bincode::deserialize(&filederserial).unwrap();
               //Unserialize in Loop
                
                //other_vectors[vectorcount ]
                //other_vectors[vectorcount].clone_from(&partyicipantfile);
                //vectorcount=vectorcount+1;
                // .clone_from(&partyicipantfile);
                if vectorcount==0
                {
                    //other_vectors[0].clone_from(&partyicipantfile);
                   // other_vectors[0]=partyicipantfile.clone();
                   //party1.clone_from(&partyicipantfile);
                   partyicipantfile1=bincode::deserialize(&filederserial).unwrap();
                    
                }
                else if vectorcount==1
                {
                    // partyicipantfile2=bincode::deserialize(&filederserial).unwrap();
                    // other_vectors[1]=partyicipantfile.clone();
                    // vectorcount=vectorcount+1;
                    partyicipantfile2=bincode::deserialize(&filederserial).unwrap();

                }
                else if vectorcount==2
                {
                    
                    // other_vectors[2]=partyicipantfile.clone();
                    // vectorcount=vectorcount+1;
                    //partyicipantfile2=bincode::deserialize(&filederserial).unwrap();
                }
                
                //other_vectors[0].clone_from(&partyicipantfile);
                countno=countno-1;vectorcount=vectorcount+1;
                
                
            }
            //decrement counter for Participant Ids
            

        }
        //DKG first Part  Round One 
        let mut other_vectors :Vec<Participant>= vec![partyicipantfile1.clone(),partyicipantfile2.clone()];
        // println!("Other vectors",);
        // println!("Other vectors",);
        // println!("Other vectors",);
        // println!("Other vectors",);
        // println!("Other vectors",);
        // println!("Other vectors",);
        // println!("Other vectors",);
        // println!("Other vectors",);

        //println!("{:?}",other_vectors);
        let mut partystate=DistributedKeyGeneration::<_>::new(&params,&id,&_p1coeffs,&mut other_vectors).or(Err(())).unwrap();

        let mut partyone_secrets: &Vec<SecretShare>=partystate.their_secret_shares().unwrap();
        // println!("Secrets Vector Done for Id {} ",id);
        // println!("{:?}",partyone_secrets);
        // println!("length of secrets{}",partyone_secrets.capacity());
        // println!("{:?}",partyone_secrets[0]);
        // println!("{:?}",partyone_secrets[1]);
        //send these secrets to other parties for proceeding to round 2
        
        //
        let countno=id;
        let mut dataserial=bincode::serialize(&partyone_secrets[0].polynomial_evaluation);
        
        //let dataa=partyone_secrets[0].polynomial_evaluation.to_bytes();
        //let xyz: subtle::CtOption<(Scalar)>=GroupEncoding::from_bytes(dataa);
        

        //partyone_secrets[0].polynomial_evaluation.add(

        let mut jsonwrite=false;
        if jsonwrite==true
        {
            let mut participantvectorpathjson = String::from("/opt/datafrost/") +&countno.to_string()+ "/participantsecretdkgjson" + &countno.to_string() + ".txt";
            let mut secretdkgfile = File::create(&participantvectorpath).expect("creation failed"); // writing 
            println!("{}",participantvectorpathjson);
            let jsondata1=serde_json::to_string(&partyone_secrets[0]);
            println!("{}",jsondata1.as_ref().unwrap());
            let jsondata2=serde_json::to_string(&partyone_secrets[1]);
            println!("{}",jsondata2.as_ref().unwrap());

            //let  jsontest: Result<SecretShare, serde_json::Error>=serde_json::from_str(jsondata.as_ref().unwrap().as_str());
            //jsontest.unwrap().
        //     if jsontest.is_ok()
        //     {
        //     println!("{:?}",jsontest.as_ref().unwrap().index);
        //    println!("{:?}",jsontest.as_ref().unwrap().polynomial_evaluation);
        //     }
        //     else {
        //         println!("unwrap error");
        //     }
        }

        let mut serdewriter=false;
        if serdewriter==true
        {
        let mut participantvectorpath = String::from("/opt/datafrost/") +&countno.to_string()+ "/participantsecretdkg" + &countno.to_string() + ".txt";
        let mut secretdkgfile = File::create(&participantvectorpath).expect("creation failed"); // writing 
        println!("{}",participantvectorpath);
        let mut dataserial=bincode::serialize(partyone_secrets);
        if dataserial.is_ok()
        {
             //The data size is 80 bytes. write and verify  if serialization is okay
                           
            println!("Verify file written in particapantsecretdkg");
            println!("{:?}",dataserial.as_ref().unwrap());
            let  length=dataserial.as_ref().unwrap().len();
            println!("length of serialized data is {}",length);
            //secretdkgfile.write_all(dataserial.unwrap().as_ref());
            //secretdkgfile.write(dataserial.as_ref().unwrap());      
            let resulatfile=secretdkgfile.write(dataserial.as_ref().unwrap()); 
            println!("{}",resulatfile.as_ref().unwrap());
            if resulatfile.is_err()
            {
                println!("error writing file {:?}",resulatfile.err());
            }
            
            
        }


        let mut filederserialdkg:[u8;80]=[0;80];
        println!("In inner loop for file read {} ",participantvectorpath);
        let mut filedeserializeddkg = match File::open(&participantvectorpath) {
            Ok(filedeserializeddkg) => filedeserializeddkg,
            Err(_) => panic!("no such file"),
        };
        filedeserializeddkg.read_exact(&mut filederserialdkg);
        //let mut secretdkgfile = File::create(&participantvectorpath).expect("creation failed"); // writing 
        //let readeaxactdkg=secretdkgfile.read_exact(&mut filederserialdkg);
        println!("{:?}",filederserialdkg.as_ref());
        let dkgfromfile: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&mut filederserialdkg);
        println!("{:?}",dkgfromfile.as_ref().unwrap());
        
        // file read excat succeful 

        //println!("{:?}",r.err());
        // if (readeaxactdkg.is_ok())
        //            {
        //             println!("{:?}",filederserialdkg.as_ref());
        //             //println!("{:?}",readeaxactdkg.as_ref().unwrap().);
        // }

        /* 
        //wait for file size 
        println!("In inner loop for file read {} ",participantvectorpath);
        std::io::stdin().read_line(&mut name);

        let readeaxactdkg=secretdkgfile.read_exact(&mut filederserialdkg);
        if (readeaxactdkg.is_ok())
                   {
                    println!("{:?}",filederserialdkg.as_ref());
                    //println!("{:?}",readeaxactdkg.as_ref().unwrap().);
        }
        let mut sharefrm1: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&filederserialdkg);
        let mut sharedscaler: Result<Scalar, Box<bincode::ErrorKind>>=bincode::deserialize(&filederserialdkg);
        println!("Testing sharefrm");
        println!("{:?}",sharefrm1.unwrap());
        println!("{:?}",sharedscaler.unwrap());
*/

        }
        else { // Working properly
            // trying to send both vectors seperately 

            let mut participantvectorpath = String::from("/opt/datafrost/") +&countno.to_string()+ "/participantsecretdkg" + &countno.to_string() + ".txt";
        let mut secretdkgfile = File::create(&participantvectorpath).expect("creation failed"); // writing 
        println!("{}",participantvectorpath);
        let mut dataserial1=bincode::serialize(&partyone_secrets[0]);
        let mut dataserial2=bincode::serialize(&partyone_secrets[1]);
        if dataserial.is_ok()
        {
             //The data size is 72 bytes. write and verify  if serialization is okay
                           
            println!("Verify file written in particapantsecretdkg");
            println!("{:?}",dataserial1.as_ref().unwrap());

            let  length=dataserial1.as_ref().unwrap().len();
            println!("length of serialized data is {}",length);

            println!("{:?}",dataserial2.as_ref().unwrap());
            let  length=dataserial2.as_ref().unwrap().len();
            println!("length of serialized data is {}",length);

            //secretdkgfile.write_all(dataserial.unwrap().as_ref());
            //secretdkgfile.write(dataserial.as_ref().unwrap());      
            let resulatfile=secretdkgfile.write(dataserial1.as_ref().unwrap()); 
            
             println!("{}",resulatfile.as_ref().unwrap());
             if resulatfile.is_err()
             {
                 println!("error writing file {:?}",resulatfile.err());
             }
             let resulatfile=secretdkgfile.write(dataserial2.as_ref().unwrap()); 
            
             println!("{}",resulatfile.as_ref().unwrap());
             if resulatfile.is_err()
             {
                 println!("error writing file {:?}",resulatfile.err());
             }
                   
        }

        //Trying to read shares seperately 36+36

         let mut filederserialdkg:[u8;72]=[0;72];
        println!("In inner loop for file read {} ",participantvectorpath);
        let mut filedeserializeddkg = match File::open(&participantvectorpath) {
            Ok(filedeserializeddkg) => filedeserializeddkg,
            Err(_) => panic!("no such file"),
        };
        filedeserializeddkg.read_exact(&mut filederserialdkg);
        //let mut secretdkgfile = File::create(&participantvectorpath).expect("creation failed"); // writing 
        //let readeaxactdkg=secretdkgfile.read_exact(&mut filederserialdkg);
        println!("{:?}",filederserialdkg.as_ref());
        let mut firstpartdkg:[u8;36]=[0;36];
        let mut secondpartdkg:[u8;36]=[0;36];
        firstpartdkg.copy_from_slice(&filederserialdkg[..36]); // left side copy 
        secondpartdkg.copy_from_slice( &filederserialdkg[36..]);
        
        //firstpart deserialized
        let dkgfromfile: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&mut firstpartdkg);
        println!("{:?}",dkgfromfile.as_ref().unwrap());
        let dkgfromfile: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&mut secondpartdkg);
        println!("{:?}",dkgfromfile.as_ref().unwrap());
        }
        println!("Wait for file writting by others ");
        println!("Wait for file writting by others ");
        println!("Wait for file writting by others ");
        println!("Wait for file writting by others ");
        println!("Wait for file writting by others ");
        std::io::stdin().read_line(&mut name);

       // go for round two and fetch secret shares from others 
        let fetching=true;
        let mut my_secret_shares :Vec<SecretShare> = vec!();

        if fetching==true 
        {

            let mut countno=totalvalue;
            let mut vectorcount=totalvalue-1;
            let mut sharecount: u32=0;
            while countno>0
            {
                if countno==id{
    
                    println!("own file not being read");
                    countno=countno-1;
                }
                           
                else {
                    println!("In inner loop for file read DKG secret share ");
                    let mut participantvectorpath = String::from("/opt/datafrost/") +&countno.to_string()+ "/participantsecretdkg" + &countno.to_string() + ".txt";
                    let mut file_secret_share = match File::open(&participantvectorpath) {
                        Ok(file_secret_share) => file_secret_share,
                        Err(_) => panic!("no such file"),
                    };
                     // initialize data with the length of file 
                    let mut filederserialdkg:[u8;72]=[0;72];
                    println!("In inner loop for file read {} ",participantvectorpath);
    
    
                    let xyfile=file_secret_share.read_exact(&mut filederserialdkg);
                    if xyfile.is_ok()
                    {
                        println!(" Secret share successful from file for {}",participantvectorpath);
                    }
                    let mut firstpartdkg:[u8;36]=[0;36];
                    let mut secondpartdkg:[u8;36]=[0;36];
                    firstpartdkg.copy_from_slice(&filederserialdkg[..36]); // left side copy 
                    secondpartdkg.copy_from_slice( &filederserialdkg[36..]);
                    
                    //firstpart deserialized
                    let  dkgfromfile1: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&mut firstpartdkg);
                    let  dkgfromfile2: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&mut secondpartdkg);
                    println!("{:?}",dkgfromfile1.as_ref().unwrap());
                    println!("{:?}",dkgfromfile2.as_ref().unwrap());
                    if dkgfromfile1.as_ref().unwrap().index==id
                    {
                        if sharecount<vectorcount
                        {
                        //     let inex:usize=sharecount as usize;
                        //     my_secret_shares[inex as usize]=dkgfromfile1.unwrap().clone();
                         sharecount=sharecount+1;
                        my_secret_shares.push(dkgfromfile1.unwrap().clone());

                        }
                        
                    }
                    if dkgfromfile2.as_ref().unwrap().index==id
                    {
                        if sharecount<vectorcount
                        {
                        //     let inex:usize=sharecount as usize;
                        //     my_secret_shares[inex as usize]=dkgfromfile2.unwrap().clone();
                         
                        my_secret_shares.push(dkgfromfile2.unwrap().clone());
                        sharecount=sharecount+1;

                        }
                        
                    }
                    
                    
                    //other_vectors[0].clone_from(&partyicipantfile);
                    countno=countno-1; //increase the counter for file read dkg
                    
                    
                }
            }
        //if (sharecount==vectorcount-1)
       

        
        
        




       
       //println!("{:?}",jsontest.as_ref().unwrap());
       //let jsondata2=serde_json::to_string(&partyone_secrets[2]);
        //println!("{}",jsondata.as_ref().unwrap());
        //let  jsontest2: Result<SecretShare, serde_json::Error>=serde_json::from_str(jsondata.as_ref().unwrap().as_str());
       //println!("{:?}",jsontest2.as_ref().unwrap());
       //jsontest.unwrap().clone()
       // let   partysample: &mut Vec<SecretShare>;
        //partysample[0]=jsontest.as_ref().unwrap().clone();
        //partysample[2]=jsontest2.unwrap();

       //let mut json :&Vec<SecretShare>=jsontest.unwrap();
       //println!("{}",jsontest.as_ref().unwrap().index);
       //println!("{:?}",jsontest.as_ref().unwrap().polynomial_evaluation);

    //    let t = U256::new(Default::default());


    //    let s = Scalar::from(56156156165 as u128);
       //let serialscaler=bincode::serialize(jsontest2.unwrap().polynomial_evaluation.as_ref());

       //let scalertest=Scalar::from(serialscaler.unwrap());
       //jsontest2.unwrap().polynomial_evaluation.clone_from(&Scalar::from(jsontest2.unwrap().polynomial_evaluation.to_bytes()));
       
        

        
        //let mut dataserial=partyone_secrets[0].tobytes();
        //dataserial.unwrap().

//             if dataserial.is_ok()
//             {
//                 //println!("{:?}",dataserial.as_ref().unwrap());
// //              //  println!("Verify file written in particapantsecretdkg");
//                 //println!("{}", dataserial.unwrap().len());  //80 bytes
//                   //80 bytes
                               
//                 println!("Verify file written in particapantsecretdkg");
//                 println!("{:?}",dataserial.as_ref().unwrap());
//                 let  length=dataserial.as_ref().unwrap().len();
//                 println!("length of serialized data{}",length);
//                 secretdkgfile.write(dataserial.as_ref().unwrap());       
                
//                             }
//             let mut filederserialdkg:[u8;80]=[80;80];

//             println!("In inner loop for file read {} ",participantvectorpath);
//             std::io::stdin().read_line(&mut name);

//             let readeaxactdkg=secretdkgfile.read_exact(&mut filederserialdkg);
//             if (readeaxactdkg.is_ok())
//                        {
//                         println!("{:?}",filederserialdkg.as_ref());
//                         //println!("{:?}",readeaxactdkg.as_ref().unwrap().);
//             }
//             let mut sharefrm1: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&filederserialdkg);
//             let mut sharedscaler: Result<Scalar, Box<bincode::ErrorKind>>=bincode::deserialize(&filederserialdkg);
//             println!("Testing sharefrm");
//             println!("{:?}",sharefrm1.unwrap());
//             println!("{:?}",sharedscaler.unwrap());

            //sharefrm1.

//Backup code bincode testing
/* 
            let countno=id;
        let mut dataserial=bincode::serialize(partyone_secrets);
        let mut participantvectorpath = String::from("/opt/datafrost/") +&countno.to_string()+ "/participantsecretdkg" + &countno.to_string() + ".txt";
        let mut secretdkgfile = File::create(&participantvectorpath).expect("creation failed"); // writing 
        println!("{}",participantvectorpath);
            if dataserial.is_ok()
            {
                //println!("{:?}",dataserial.as_ref().unwrap());
//              //  println!("Verify file written in particapantsecretdkg");
                //println!("{}", dataserial.unwrap().len());  //80 bytes
                  //80 bytes
                               
                println!("Verify file written in particapantsecretdkg");
                println!("{:?}",dataserial.as_ref().unwrap());
                secretdkgfile.write(dataserial.as_ref().unwrap());       
                
                            }
            let mut filederserialdkg:[u8;80]=[80;80];

            println!("In inner loop for file read {} ",participantvectorpath);
            std::io::stdin().read_line(&mut name);

            let readeaxactdkg=secretdkgfile.read_exact(&mut filederserialdkg);
            if (readeaxactdkg.is_ok())
                       {
                        println!("{:?}",filederserialdkg.as_ref());
                        //println!("{:?}",readeaxactdkg.as_ref().unwrap().);
            }
            let mut sharefrm1: Result<SecretShare, Box<bincode::ErrorKind>>=bincode::deserialize(&filederserialdkg);
            println!("Testing sharefrm");
            println!("{:?}",sharefrm1.unwrap());


            */
        //80 bytes

        
        // secretdkgfile.write(dataserial.as_ref().unwrap());
        // let serialsecretdkgfile1=bincode::serialize(partyone_secrets);


        // let mut filedeserialized = match File::open(&participantvectorpath) {
        //     Ok(filedeserialized) => filedeserialized,
        //     Err(_) => panic!("no such file"),
        // };
        

        //let mut partystate2=partystate.clone();
        
        //partyone_secrets
        
        //partystate=partystate.to_round_two(other_vectors);

/* // problem with round 2 KG 
        let mut partystate2=partystate.clone();
        
        let mut partystaternd2 = partystate2.clone().to_round_two( partystate2.their_secret_shares().unwrap().to_vec());
        
        let partystaternd2=partystaternd2.unwrap();

        let mut blabblabbalb=partystaternd2.finish(&p1.public_key().unwrap()).unwrap();
        let mut partygroupkey= blabblabbalb.0;
        //let mut partysecretkey=blabblabbalb.as_mut().unwrap().1;
        println!("Groupkey");
        println!("{:?}",partygroupkey);

         */

        // println!("Secret key full ");
        // println!("{:?}",&mut blabblabbalb.1);
        // println!("Public key from Private key ");
        // println!("{:?}",&mut blabblabbalb.1.to_public());
        // println!("Public key from Pubic key ");
        // let pkey=blabblabbalb.unwrap().1.to_public();
        // println!("{:?}",pkey);

        //partystaternd2.unwrap();
        //let (party_group_key: GroupKey , party_secret_key: SecretKey)=partystaternd2.unwrap().finish(&p1.public_key().unwrap());
        //let (xy, GroupKey, xy3, SecretKey)=partystaternd2.unwrap().finish(&p1.public_key().unwrap());
        //let party_groupkey=xy.iter();
           // let xy=partystaternd2.finish(&p1.public_key().unwrap());
            //println!("{:?}", xy);
        


       /*
        let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
        let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
                                                             &mut alice_other_participants).or(Err(()))?;
        let alice_their_secret_shares = alice_state.their_secret_shares()?;
        let alice_state = alice_state.to_round_two(alice_my_secret_shares)?;
        //! # let (alice_group_key, alice_secret_key) = alice_state.finish(&alice.public_key().unwrap())?;
         */
      

            // let mut Othervectors :Vec<Participant>=vec!();

            

// Trying to use Serde Json to convert Affine point back //       
    //    let mut p1_participantb64=serde_json::to_value(p1.commitments).unwrap() ;
    //    let mut p1affine:AffinePoint=serde_json::from_value(p1_participantb64).unwrap();
    //          println!("{:?}",p1affine);


        //p1frombytes.unwrap().
        

    //   let mut p1_participantb64=serde_json::to_value(p1.commitments).unwrap() ;
    //   //println!("{:?}",p1_participantb64);
    //   //println!("{:?}",serde_json::json!(p1_participantb64));
    //   let jsonval=serde_json::json!(p1_participantb64);
    //   let jsonpart:Result<Participant, serde_json::Error> =serde_json::from_value(jsonval);
    //   if jsonpart.is_err()
    //   {
    //     println!("jsonpart error ");
    //     println!("jsonpart error {:?}",jsonpart.err());
    //   }
      


      

        // let jsojxyz: Result<serde_json::Value, serde_json::Error>=serde_json::from_slice(bufstrng.as_ref());
        // println!("{:?}",jsojxyz.unwrap());


        //let p1xyz=serde::Deserialize::<Participant>(&bufstrng);
        // //p1_participant.shrink_to_fit();
        // //p1_participant.
        // // let mut p1frombytes=p1frombytes.unwrap();
        // match p1frombytes {
        //     Ok(val)=>{
        //         println!("ok {:?}",val);
        //     },
        //     Err(err)=>{
        //         println!("error {:?}",err);
        //     }
        // }
        //p1frombytes.
        //let p1bytes: Vec<u8>=Participant::into(p1);
       /* 
        ///
       
        
        */

        // let participant1 =p1;
        // let a=Secp256k1::new();
        

        //sec1::EncodedPoint::as_bytes(&self)
        //let mut p1_other_participants: Vec<Participant> = vec!(p1.clone());

        // Try writing vector 
        //let mut publickeytofile = pathfile + "public" + &lines[0].to_string() + ".vec.txt";
        //let mut data_file = File::create(publickeytofile).expect("creation failed"); // writing code for file
        //let xyzzzz=bincode::Serializer::from(&p1);
        //let serialdata=bincode::serialize(&p1);
        //data_file.write_all(p1_other_participants.seri
            //participant1.clone_into(xyza);
            //frost_secp256k1::keygen::Participant
            

            //let tobyes :[u8]=p1.into();


//        let mut publickeyfile = String::from("/opt/datafrost/")        + n.to_string().trim()         + "/public"         + n.to_string().trim()         + ".vec.txt";
        

        
        

        
        
        }    
        


// final calls 

    //  let mut partystate2=partystate.clone();
  //partystate2=partystate2.to_round_two(my_secret_shares).unwrap();
  //let (p1_group_key: GroupKey, _p1_secret_key: k256::SecretKey) = partystate2.finish(&p1.public_key().unwrap());
  //println!("{:?}",my_secret_shares);
  //println!("partystate");
//   println!("{:?}",partystate);
//   println!("");
//   println!("");
//   println!("partystate secret shares");
//   println!("");
//   println!("");
//   println!("");
//   println!("");

//   println!("{:?}",partystate.their_secret_shares());
  
  
  //partystate.their_secret_shares().
  
  
  let mut partystate2: DistributedKeyGeneration<frost_secp256k1::keygen::RoundTwo>=partystate.to_round_two(my_secret_shares).unwrap();
  
  //let resultxy= partystate.finish(&p1.public_key().unwrap());

  //let finastate: Result<DistributedKeyGeneration<frost_secp256k1::keygen::RoundTwo>, ()>=partystate.to_round_two(my_secret_shares);

  //let (p1groupkey: frost_secp256k1::keygen::GroupKey, p1secretkey: frost_secp256k1::keygen::SecretKey)=partystate.finish(&p1.public_key().unwrap());
  //let finalvalue=partystate.finish(&p1.public_key().unwrap());
  //let resultxy= finastate.unwrap().finish(&p1.public_key().unwrap());
  //let resultxy= partystate.finish(&p1.public_key().unwrap());
//   println!("partystate2");
//   println!("");
//   println!("");

//   println!("{:?}",partystate2);
  //let resultxy=partystate2.finish(&p1.public_key().unwrap());
//   println!("full value {:?}",resultxy);
//   println!("");
//   println!("");
  let supms=partystate2.finish(&p1.public_key().unwrap());
  let Gkey=supms.as_ref().unwrap().0;
  let skey=supms.unwrap().1;
  let pkey=skey.to_public();
  println!("public key ");
  println!("{:?}",pkey.share);
  println!("Group key ");
  println!("{:?}",Gkey);
  println!("Secret key ");
  println!("{:?}",pkey.share);
  //skey.sign(message_hash, group_key, my_secret_commitment_share_list, my_commitment_share_index, signers)
  


  //println!("{:?}",supms.as_ref().unwrap().0);
  //println!("{:?}",supms.as_ref().unwrap().1);

  //let gkey=keygen::DistributedKeyGeneration::calculate_group_key(&partystate2, &p1.commitments);
  
 
    // let my_secret_shares2 = partystate2.state.my_secret_shares.as_ref().ok_or(())?;
    // let mut key = my_secret_shares2.iter().fold(Scalar::ZERO, |acc, x| acc + x.polynomial_evaluation);

    // key += self.state.my_secret_share.polynomial_evaluation;
 let supms=partystate2.finish(&p1.public_key().unwrap());
  let Gkey=supms.as_ref().unwrap().0;
  let skey=supms.unwrap().1;
  let pkey=skey.to_public();
  println!("public key ");
  println!("{:?}",pkey.share);
  println!("Group key ");
  println!("{:?}",Gkey);
  println!("Secret key ");
  println!("{:?}",pkey.share);
  //skey.sign(message_hash, group_key, my_secret_commitment_share_list, my_commitment_share_index, signers)1
 

  
  //resultxy.iter().cyc
  //println!("Groupkey");println!("{:?}",resultxy.iter().next());
//  println!("Secretkey");println!("{:?}",resultxy.iter().next());

  */
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
    


