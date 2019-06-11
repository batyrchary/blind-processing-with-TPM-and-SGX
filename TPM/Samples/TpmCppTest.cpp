/*++

Copyright (c) 2013, 2014  Microsoft Corporation
Microsoft Confidential

*/
#include "stdafx.h"
#include "Tpm2.h"
#include "Samples.h"

#define _CRT_SECURE_NO_WARNINGS
using namespace TpmCpp;

void getRandomBytes(Tpm2 tpm)
{
	// Get 20 bytes of random data from
	std::vector<BYTE> rand = tpm.GetRandom(20);

	// Print it out.
	cout << "Random bytes: " << rand << endl;
}

void SigningPrimary(Tpm2 tpm)
{
	// To create a primary key the TPM must be provided with a template. This is for an RSA1024 signing key.
	vector<BYTE> NullVec;
	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::sign |
		TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		NullVec,
		TPMS_RSA_PARMS( TPMT_SYM_DEF_OBJECT::NullObject(), TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA1), 1024, 65537), TPM2B_PUBLIC_KEY_RSA(NullVec));

	// Set the use-auth for the key. Note the second parameter is NULL because we are asking the TPM to create a new key.
	ByteVec userAuth = ByteVec{ 1, 2, 3, 4 };
	TPMS_SENSITIVE_CREATE sensCreate(userAuth, NullVec);

	// We don't need to know the PCR-state with the key was created so set this parameter to a null-vector.
	vector<TPMS_PCR_SELECTION> pcrSelect{};

	// Ask the TPM to create the key
	CreatePrimaryResponse newPrimary = tpm.CreatePrimary(tpm._AdminOwner, sensCreate, templ, NullVec, pcrSelect);


	// Print out the public data for the new key. Note the "false" parameter to
	// ToString() "pretty-prints" the byte-arrays.
	cout << "New RSA primary key" << endl << newPrimary.outPublic.ToString(false) << endl;

	// Sign something with the new key. First set the auth-value in the handle.
	TPM_HANDLE& signKey = newPrimary.handle;
	signKey.SetAuth(userAuth);

	TPMT_HA dataToSign = TPMT_HA::FromHashOfString(TPM_ALG_ID::SHA1, "abc");

	auto sig = tpm.Sign(signKey, dataToSign.digest, TPMS_NULL_SIG_SCHEME(), TPMT_TK_HASHCHECK::NullTicket());

	cout << "Signature:" << endl << sig.ToString(false) << endl;

	// Use TSS.C++ to validate the signature
	bool sigOk = newPrimary.outPublic.ValidateSignature(dataToSign.digest, *sig.signature);
	_ASSERT(sigOk);

	tpm.FlushContext(newPrimary.handle);

	return;
}

void PWAPAuth(Tpm2 tpm)
{
	// Most TPM entities are referenced by handle
	TPM_HANDLE platformHandle = TPM_HANDLE::FromReservedHandle(TPM_RH::PLATFORM);

	// The TSS.C++ TPM_HANDLE class also includes an authValue to be used whenever this handle is used.
	vector<BYTE> NullAuth{};
	platformHandle.SetAuth(NullAuth);

	// If we issue a command that needs authorization TSS.C++ automatically uses the authValue contained in the handle.
	//tpm.Clear(platformHandle);

	// We can use the "old" platform-auth to install a new value
	//vector<BYTE> newAuth{ 1, 2, 3, 4, 5 };
	//tpm.HierarchyChangeAuth(platformHandle, newAuth);

	// If we want to do further TPM administration we must associate the new authValue with the handle.
	//platformHandle.SetAuth(newAuth);
	//tpm.Clear(platformHandle);

	// And put things back the way they were
	//tpm.HierarchyChangeAuth(platformHandle, NullAuth);

	return;
}

void Errors(Tpm2 tpm)
{
	// Construct an ilegal handle value
	TPM_HANDLE invalidHandle((UINT32)-1);

	// Try to read the associated information
	try { tpm.ReadPublic(invalidHandle); }
	catch (system_error e) 
	{
		// Note that the following e.what() may produce a platform specific result. For example,
		//this error typically corresponds to the ERFKILL errno on a linux platform.
		cout << "As expected, the TPM returned an error:" << e.what() << endl;
	}

	// We can also suppress the exception and do an explit error check
	tpm._AllowErrors().ReadPublic(invalidHandle);

	if (tpm._GetLastError() != TPM_RC::SUCCESS) 
	{
		cout << "Command failed, as expected." << endl;
	}

	// If we WANT an error we can turn things around so that an exception is
	// thrown if a specific error is _not_ seen.
	tpm._ExpectError(TPM_RC::VALUE).ReadPublic(invalidHandle);

	// Or any error
	tpm._DemandError().ReadPublic(invalidHandle);

	return;
}

void Structures(Tpm2 tpm)
{
	UINT32 pcrIndex = 0;

	// "Event" PCR-0 with the binary data
	//tpm.PCR_Event(pcrIndex, std::vector<BYTE> { 0, 1, 2, 3, 4 });

	// Read PCR-0
	vector<TPMS_PCR_SELECTION> pcrToRead{ TPMS_PCR_SELECTION(TPM_ALG_ID::SHA1, pcrIndex) };
	PCR_ReadResponse pcrVal = tpm.PCR_Read(pcrToRead);

	// Now print it out in pretty-printed human-readable form
	cout << "Text form of pcrVal" << endl << pcrVal.ToString() << endl;
	
	// Now in JSON
	string pcrValInJSON = pcrVal.Serialize(SerializationType::JSON);
	cout << "JSON form" << endl << pcrValInJSON << endl;

	// Now in TPM-binary form
	vector<BYTE> tpmBinaryForm = pcrVal.ToBuf();
	cout << "TPM Binary form:" << endl << tpmBinaryForm << endl;

	// Now rehydrate the JSON and binary forms to new structures
	PCR_ReadResponse fromJSON, fromBinary;
	fromJSON.Deserialize(SerializationType::JSON, pcrValInJSON);
	fromBinary.FromBuf(tpmBinaryForm);

	// And check that the reconstituted values are the same as the originals with the built-in value-equality operators.

	if (pcrVal != fromJSON) 
	{
		cout << "JSON Deserialization failed" << endl;
	}

	if (pcrVal == fromBinary) 
	{
		cout << "Binary serialization succeeded" << endl;
	}
	
	return;
}

void HMACSessions(Tpm2 tpm)
{
	// Start a simple HMAC authorization session: no salt, no encryption, no bound-object.
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::HMAC, TPM_ALG_ID::SHA1);

	// Perform an operation authorizing with an HMAC
//	tpm._Sessions(s).Clear(tpm._AdminPlatform);

	// A more terse way of associating an explicit session with a command
//	tpm(s).Clear(tpm._AdminPlatform);

	// And clean up
//	tpm.FlushContext(s);

	return;
}

void SimplePolicy(Tpm2 tpm)
{
	// A TPM policy is a list or tree of Policy Assertions. We will create a
	// policy that authorizes actions when they are issued at locality 1.

	// Create the simple policy "tree"
	PolicyTree p(PolicyLocality(TPMA_LOCALITY::LOC_ONE, ""));

	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// Now configure the TPM so that storage-hierarchy actions can be performed by any sofware that can 
	//issue commands at locality 1.  We do this using the platform auth-value

//	tpm.SetPrimaryPolicy(tpm._AdminPlatform, policyDigest.digest, TPM_ALG_ID::SHA1);

	// Now execute the policy
	//AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

	// Execute the policy using the session. This issues a sequence of TPM operations to "prove" to the
	//TPM that the policy is satisfied. In this very simple case Execute() will call
	//p.Execute(tpm, s);

	// Execute a Clear operation at locality 1 with the policy session
	//tpm._GetDevice().SetLocality(1);
	//tpm(s).Clear(tpm._AdminPlatform);
	//tpm._GetDevice().SetLocality(0);
	//tpm.FlushContext(s);

	// But the command should fail at locality zero
	//s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	//p.Execute(tpm, s);

//	tpm(s)._ExpectError(TPM_RC::LOCALITY).Clear(tpm._AdminPlatform);
	//tpm.FlushContext(s);

	// Clear the hierarch policy
	//tpm.SetPrimaryPolicy(tpm._AdminPlatform, vector<BYTE>(), TPM_ALG_ID::_NULL);

	return;
}

void ThreeElementPolicy(Tpm2 tpm)
{
	// We will construct a policy that needs pcr-15 to be set to a certain value (a value that we will measure) 
	//and needs physical-presence to be asserted and that the command be issued at locality 1.

	// First set PCR-15 to an "interesting" value and read it.
	UINT32 pcr = 15;
	TPM_ALG_ID bank = TPM_ALG_ID::SHA1;
//	tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec{ 1, 2, 3, 4 });

	/*
	// Read the current value
	vector<TPMS_PCR_SELECTION> pcrSelection = TPMS_PCR_SELECTION::GetSelectionArray(bank, pcr);
	auto startPcrVal = tpm.PCR_Read(pcrSelection);
	auto currentValue = startPcrVal.pcrValues;

	// Create a policy naming this PCR+value, PP, and locality - 1
	PolicyTree p(PolicyPcr(currentValue, pcrSelection), PolicyPhysicalPresence(), PolicyLocality(TPMA_LOCALITY::LOC_TWO));
	
	// Get the policy digest
	TPMT_HA policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// set the policy so that pcr-20 can only be extended with this policy
	TPM_HANDLE pcr2 = TPM_HANDLE::PcrHandle(20);
	tpm.PCR_SetAuthPolicy(tpm._AdminPlatform, policyDigest.digest, TPM_ALG_ID::SHA1, pcr2);
	
	// Show that we can no longer extend.
	tpm._ExpectError(TPM_RC::AUTH_TYPE).PCR_Event(pcr2, vector<BYTE> {0, 1});

	// But we can perform the action with the appropriate policy + assertion of PP
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, s);

	// Use the session + PP to execute the command
	tpm._GetDevice().PPOn();
	tpm._GetDevice().SetLocality(2);
	auto pcrAfterExtend = tpm(s).PCR_Event(pcr2, vector<BYTE> {0, 1});
	tpm._GetDevice().SetLocality(0);
	tpm._GetDevice().PPOff();
	tpm.FlushContext(s);

	cout << "PCR after policy-based extend: " << endl << pcrAfterExtend[0].ToString() << endl;

	// Change the PCR and show that this no longer works
	tpm.PCR_Event(TPM_HANDLE::PcrHandle(pcr), ByteVec{ 1, 2, 3, 4 });

	bool worked = true;
	s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);

	try {
		p.Execute(tpm, s);
	}
	catch (exception) {
		worked = false;
	}

	_ASSERT(!worked);

	if (!worked) {
		cout << "Policy failed after PCR-extend, as expected." << endl;
	}

	tpm.FlushContext(s);

	// Reset the PCR-policy
	tpm.PCR_SetAuthPolicy(tpm._AdminPlatform,
		vector<BYTE>(),
		TPM_ALG_ID::_NULL,
		pcr2);
	
	*/
	return;
}

void PolicyOrSample(Tpm2 tpm)
{

	// Create a policy demanding either locality-1 OR physical presence In this sample we execute the policy 
	//and check the TPM-policy-digest but do not attempt to use the policy session to authorize an action.

	PolicyTree branch1(PolicyLocality(TPMA_LOCALITY::LOC_ONE, "loc-branch"));
	PolicyTree branch2(PolicyPhysicalPresence("pp-branch"));

	PolicyTree p(PolicyOr(branch1.GetTree(), branch2.GetTree()));

	// Get the policy-digest
	auto policyDigest = p.GetPolicyDigest(TPM_ALG_ID::SHA1);

	// Execute one branch...
	AUTH_SESSION s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, s, "loc-branch");
	auto policyDigest2 = tpm.PolicyGetDigest(s);

	_ASSERT(policyDigest.digest == policyDigest2);

	if (policyDigest.digest == policyDigest2) 
	{
		cout << "PolicyOR (branch1) digest is as expected:" << endl << policyDigest2 << endl;
	}

	tpm.FlushContext(s);

	// And then the other branch
	s = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA1);
	p.Execute(tpm, s, "pp-branch");
	policyDigest2 = tpm.PolicyGetDigest(s);

	_ASSERT(policyDigest.digest == policyDigest2);

	if (policyDigest.digest == policyDigest2) {
		cout << "PolicyOR (branch1) digest is as expected:" << endl << policyDigest2 << endl;
	}

	tpm.FlushContext(s);
}


int main()
{
	////////////////////////////////////////////init////////////////////////////////////////////////////

	////////////////////////////////////////////init////////////////////////////////////////////////////	
	std::cout << "initializing TPM" << endl;

	//TpmTbsDevice device;
	//if (!device.Connect()) { cerr << "Could not connect to the TPM device"; return 0; }
	//Tpm2 tpm(device);


	TpmTcpDevice device;
	if (!device.Connect("127.0.0.1", 2321)) { std::cout << "error in connecting" << endl; }
	Tpm2 tpm(device);

	device.PowerOff();
	device.PowerOn();
	tpm.Startup(TPM_SU::CLEAR);
	
	int num;
	printf("number:");
	scanf_s("%d", &num);
	/////////////////////////////////////////////////////////////////////////////////////////////////

//	getRandomBytes(tpm);
	
//	SigningPrimary(tpm); // create a primary key // sign something with the new key // validate the signature
	
//	PWAPAuth(tpm); //handle, authorization
	
//	Errors(tpm); //error handling

//	Structures(tpm);//reading pcr values

//	HMACSessions(tpm);

//	SimplePolicy(tpm);

//	ThreeElementPolicy(tpm);

//	PolicyOrSample(tpm);
	


//	Samples s;
//	s.myNV();


	//s.Rand();
	//s.PCR();		//some errors
	//s.Locality(); //some errors
	//s.Hash();		//error related to PCR extend event
	//s.HMAC();
	//s.GetCapability();
	//s.NV();
	//s.PrimaryKeys(); //create primary key and sign the data and put key into nv by evictcontrol
	//s.AuthSessions(); //error related to tpm.clear()
	//s.Async();
	//s.PolicySimplest();
	//s.PolicyLocalitySample(); //error
	//s.PolicyPCRSample(); //error
	//s.ChildKeys();
	//s.PolicyORSample();//error related to pcr
	//s.CounterTimer();
	//s.Attestation(); //quote also verification, quote with pcr quote with key, quote with time, quote with nv(error) 
	//s.Admin(); //most probably will give error
	//s.DictionaryAttack(); //admin things error
	//s.PolicyCpHash(); //error
	//s.PolicyTimer(); //error
	//s.PolicyWithPasswords();
	//s.Unseal();			//took too long
	//s.Serializer();		//error
	//s.SessionEncryption();		//error
	//s.ImportDuplicate();		
	//s.MiscAdmin();		//error
	//s.RsaEncryptDecrypt();	
	//s.Audit();		//error	
	//s.Activate();		//toook too long
	//s.SoftwareKeys();	//
	//s.PolicySigned();
	//s.PolicyAuthorizeSample();
	//s.PolicySecretSample();
	//s.EncryptDecryptSample();			//error
	//s.SeededSession();			//took too lonng
	//s.PolicyNVSample();			//error
	//s.PolicyNameHashSample();		//error
	
	
	
	
	
	
	return 0;
}



/*
#include "Samples.h"

// The name "DllInit" is misleading on non-WIN32 platforms but
// the purpose of the routine is the same, initializing TSS.CPP.
extern void DllInit();

#ifdef WIN32
_CrtMemState MemState;

int _tmain(int argc, _TCHAR *argv[])
{
	cout << "Hello" << endl;


    _CrtMemCheckpoint(&MemState);

    Samples s;
	cout << "Hello2" << endl;
	
    //s.RunAllSamples();

    HMODULE h = LoadLibrary(_T("TSS.CPP.dll"));
    _ASSERT(h != NULL);

    BOOL ok = FreeLibrary(h);
    _ASSERT(ok);
    _CrtMemDumpAllObjectsSince(&MemState);
	
    return 0;
}
#endif

#ifdef __linux__
int main(int argc, char *argv[])
{
    DllInit();

    try {
        Samples s;
        s.RunAllSamples();
    }
    catch (const runtime_error& exc) {
        cerr << "TpmCppTester: " << exc.what() << "\nExiting...\n";
    }

    return 0;
}
#endif


*/