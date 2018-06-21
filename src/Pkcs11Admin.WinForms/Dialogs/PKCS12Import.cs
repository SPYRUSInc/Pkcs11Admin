//
// Extension to PKCS11Admin to support importing of PKCS #12 Files
// PF
// 28/10/2017
// 
using Net.Pkcs11Interop.Common;
using System;
using System.IO;
using System.Collections.Generic;
using System.Windows.Forms;
using System.Security.Cryptography;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Admin.Configuration;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Net.Pkcs11Admin.WinForms.Dialogs
{
    partial class PKCS12ImportDialog : Form
    {
        private Pkcs11Slot _slot = null;

        public PKCS12ImportDialog(Pkcs11Slot slot)
        {
            InitializeComponent();
            PKCS12_CKA_ID_GenerationMethodComboBox.SelectedIndex = 0;
            _slot = slot;
        }

        private void PKCS12BrowseButton_Click(object sender, EventArgs e)
        {
            var openFileDialog = new System.Windows.Forms.OpenFileDialog();
            openFileDialog.Filter = "PKCS#12 Files|*.p12;*.pfx";
            openFileDialog.InitialDirectory = @"C:\";
            openFileDialog.Title = "Please select PKCS#12 file to import.";
            if (openFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                PKCS12FilenameTextBox.Text = openFileDialog.FileName;
            }
        }

        private void PKCS12OKButton_Click(object sender, EventArgs e)
        {
            PKCS12CancelButton.Enabled = false;
            PKCS12OKButton.Enabled = false;

            Cursor.Current = Cursors.WaitCursor;

            if (ImportPKCS12(PKCS12FilenameTextBox.Text, PKCS12PasswordTextBox.Text, PKCS12FriendlyNameTextBox.Text, PKCS12ImportPublicKeyCheckBox.Checked, PKCS12_CKA_ID_GenerationMethodComboBox.SelectedIndex))
            {
                Cursor.Current = Cursors.Default;
                PKCS12OKButton.Enabled = true;
                PKCS12CancelButton.Enabled = true;
                this.DialogResult = System.Windows.Forms.DialogResult.OK;
                this.Close();
            } else
            {
                Cursor.Current = Cursors.Default;
                PKCS12OKButton.Enabled = true;
                PKCS12CancelButton.Enabled = true;
            }
        }

        private void PKCS12CancelButton_Click(object sender, EventArgs e)
        {
            this.DialogResult = System.Windows.Forms.DialogResult.OK;
            this.Close();
        }

        //
        // Import PKCS #12 file using specified password.
        // This will result in the creation of RSA private key object, RSA certificate object and optionally
        // an RSA public key object.
        // The caller can specify a PKCS #12 friendlyname which will be used as the CKA_LABEL value. This is
        // useful for when the requirements for the import are a particular name.
        // 
        private bool ImportPKCS12(string filename, string password, string friendlyName, bool importPublicKey, int ckaIDGenerationMethod)
        {
            const int KEYCERTSIGN = 5;

            bool firefoxCompatibleCKAID = false;
            byte[] firefox_CKA_ID_Value = null;
            byte[] subjectPublicKeyInfo_CKA_ID = null;

            if (filename.Length == 0)
            {
                return true;     // Nothing to do
            }

            if (ckaIDGenerationMethod == 1)
            {
                firefoxCompatibleCKAID = true;
            }

            Pkcs12Store store = null;
            using (StreamReader reader = new StreamReader(filename))
            {
                try
                {
                    store = new Pkcs12Store(reader.BaseStream, password.ToCharArray());
                } catch (IOException ex)
                {
                    // Password is invalid or file corrupted
                    MessageBox.Show(ex.Message, "Error Importing PKCS #12", MessageBoxButtons.OK);
                    return false;
                }

                //
                // If we have been request to have CKA_ID compatible with Firefox then
                // we need to pre-calculate the value.
                // 
                if (firefoxCompatibleCKAID)
                {
                    foreach (string n in store.Aliases)
                    {
                        AsymmetricKeyEntry key = store.GetKey(n);

                        if (key.Key.IsPrivate)
                        {
                            RsaPrivateCrtKeyParameters parameters = key.Key as RsaPrivateCrtKeyParameters;

                            using (SHA1Managed sha1Managed = new SHA1Managed())
                            {
                                firefox_CKA_ID_Value = sha1Managed.ComputeHash(parameters.Modulus.ToByteArrayUnsigned());
                            }
                        }
                    }
                }

                foreach (string n in store.Aliases)
                {
                    byte[] subjectNameBytes = null;
                    byte[] modulusBytes = null;
                    byte[] publicExponentBytes = null;

                    //
                    // Certificate Chain
                    // 
                    X509CertificateEntry[] ch = store.GetCertificateChain(n);
                    if (ch.Length > 0)
                    {
                        for (int i = 0; i < ch.Length; ++i)
                        {
                            bool isCACertificate = false;
                            bool[] keyUsage = ch[i].Certificate.GetKeyUsage();

                            // Only CA certificates can have KEYCERTSIGN keyUsage
                            if (keyUsage[KEYCERTSIGN])
                            {
                                // CA certificate
                                isCACertificate = true;
                            }
                            else
                            {
                                // User certificate
                                isCACertificate = false;
                            }

                            if (isCACertificate)
                            {
                                // CA Certificate - just generate thumbprint required for certificate import
                                using (SHA1Managed sha1Managed = new SHA1Managed())
                                {
                                    // CKA_ID as per PKCS #11 specification - it should be the SubjectKeyIdentifier.
                                    // As per RFC3280 this should be the BitString alone, not including the algorithm information.
                                    subjectPublicKeyInfo_CKA_ID = sha1Managed.ComputeHash(ch[i].Certificate.CertificateStructure.SubjectPublicKeyInfo.PublicKeyData.GetOctets());
                                }
                            } else { 
                                if (importPublicKey)
                                {
                                    // Get Subject Name Bytes
                                    subjectNameBytes = ch[i].Certificate.SubjectDN.GetDerEncoded();
                                }

                                if (firefoxCompatibleCKAID == false)
                                {
                                    using (SHA1Managed sha1Managed = new SHA1Managed())
                                    {
                                        // CKA_ID as per PKCS #11 specification - it should be the SubjectKeyIdentifier.
                                        // As per RFC3280 the subjectKeyIdentifier should be the SHA1 hash of the BitString component alone.
                                        subjectPublicKeyInfo_CKA_ID = sha1Managed.ComputeHash(ch[i].Certificate.CertificateStructure.SubjectPublicKeyInfo.PublicKeyData.GetOctets());
                                    }
                                }
                            } 

                            List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
                            if (friendlyName != null && friendlyName.Length > 0)
                            {
                                objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, friendlyName));
                            }
                            else
                            {
                                objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, n));
                            }
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, ch[i].Certificate.SubjectDN.GetDerEncoded()));
                            if (firefoxCompatibleCKAID)
                            {
                                objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, firefox_CKA_ID_Value));
                            } else
                            {
                                objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, subjectPublicKeyInfo_CKA_ID));
                            }
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_ISSUER, ch[i].Certificate.IssuerDN.GetDerEncoded()));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_SERIAL_NUMBER, ConvertBackToASN1Integer(ch[i].Certificate.SerialNumber.ToByteArray())));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, ch[i].Certificate.GetEncoded()));

                            // Create PKCS #11 Certificate Object
                            try
                            {
                                _slot.CreateObject(objectAttributes);
                            }
                            catch (Exception ex)
                            {
                                MessageBox.Show(ex.Message, "Error Creating PKCS #12 Certificate Object", MessageBoxButtons.OK);
                            }
                        }
                    }

                    //
                    // Private Key
                    // 
                    if (store.IsKeyEntry(n))
                    {
                        AsymmetricKeyEntry key = store.GetKey(n);

                        if (key.Key.IsPrivate)
                        {
                            RsaPrivateCrtKeyParameters parameters = key.Key as RsaPrivateCrtKeyParameters;

                            List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, false));
                            if (friendlyName != null && friendlyName.Length > 0)
                            {
                                objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, friendlyName));
                            } else
                            {
                                objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, n));
                            }
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, subjectNameBytes));
                            if (firefoxCompatibleCKAID)
                            {
                                objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, firefox_CKA_ID_Value));
                            }
                            else
                            {
                                objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, subjectPublicKeyInfo_CKA_ID));
                            }
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_SENSITIVE, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_DECRYPT, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_SIGN_RECOVER, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_UNWRAP, true));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_DERIVE, false));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_EXTRACTABLE, false));
                            //objectAttributes.Add(new ObjectAttribute(CKA.CKA_ALWAYS_AUTHENTICATE, true)); // NOTE: This causes OpenSC to prompt for password mid-stream during execution

                            // First byte is a sign indicator (00 indicates positive)
                            byte[] modulus = RemoveLeadingZeroIfRequired(parameters.Modulus.ToByteArray());
                            byte[] privateExponent = RemoveLeadingZeroIfRequired(parameters.Exponent.ToByteArray());
                            byte[] prime1 = RemoveLeadingZeroIfRequired(parameters.P.ToByteArray());
                            byte[] prime2 = RemoveLeadingZeroIfRequired(parameters.Q.ToByteArray());
                            byte[] exponent1 = RemoveLeadingZeroIfRequired(parameters.DP.ToByteArray());
                            byte[] exponent2 = RemoveLeadingZeroIfRequired(parameters.DQ.ToByteArray());
                            byte[] coefficient = RemoveLeadingZeroIfRequired(parameters.QInv.ToByteArray());
                            byte[] publicExponent = RemoveLeadingZeroIfRequired(parameters.PublicExponent.ToByteArray());

                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, publicExponent));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS, modulus));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE_EXPONENT, privateExponent));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIME_1, prime1));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIME_2, prime2));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_EXPONENT_1, exponent1));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_EXPONENT_2, exponent2));
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_COEFFICIENT, coefficient));

                            if (importPublicKey)
                            {
                                modulusBytes = modulus;
                                publicExponentBytes = publicExponent;
                            }

                            // Create PKCS #11 Object
                            try
                            {
                                _slot.CreateObject(objectAttributes);
                            } 
                            catch (Exception ex)
                            {
                                MessageBox.Show(ex.Message, "Error Creating PKCS #12 Private Key Object", MessageBoxButtons.OK);
                            }
                        }
                    }

                    //
                    // Public Key
                    //
                    if (importPublicKey)
                    {
                        List<ObjectAttribute> objectAttributes = new List<ObjectAttribute>();
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_TOKEN, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_PRIVATE, false));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODIFIABLE, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA));
                        if (friendlyName != null && friendlyName.Length > 0)
                        {
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, friendlyName));
                        }
                        else
                        {
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_LABEL, n));
                        }     
                        if (firefoxCompatibleCKAID)
                        {
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, firefox_CKA_ID_Value));
                        }
                        else
                        {
                            objectAttributes.Add(new ObjectAttribute(CKA.CKA_ID, subjectPublicKeyInfo_CKA_ID));
                        }
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_DERIVE, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_SUBJECT, subjectNameBytes));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_ENCRYPT, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_VERIFY_RECOVER, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_WRAP, true));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_MODULUS, modulusBytes));
                        objectAttributes.Add(new ObjectAttribute(CKA.CKA_PUBLIC_EXPONENT, publicExponentBytes));

                        // Create PKCS #11 Object
                        try
                        {
                            _slot.CreateObject(objectAttributes);
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(ex.Message, "Error Creating PKCS #12 Public Key Object", MessageBoxButtons.OK);
                        }
                    }
                }
            }

            return true;
        }

        //
        // Strip Leading Zero Byte from BitInteger Byte Arrays if Postiive Signing Bit
        //
        private byte[] RemoveLeadingZeroIfRequired(byte[] t)
        {
            // Check for BigInteger signing bit indicating positive.
            if (t[0] == 0)
            {
                // Strip leading zero
                byte[] newArray = new byte[t.Length - 1];
                Array.Copy(t, 1, newArray, 0, newArray.Length);
                return newArray;
            }
            else
            {
                return t;   // Just pass byte array back it is OK.
            }
        }

        private byte[] ConvertBackToASN1Integer(byte[] serialNumber)
        {
            byte[] newArray = new byte[serialNumber.Length + 2];
            newArray[0] = 0x02;
            newArray[1] = (byte)serialNumber.Length;
            Array.Copy(serialNumber, 0, newArray, 2, serialNumber.Length);
            return newArray;
        }

        private void DisplayAttributes(List<Tuple<ObjectAttribute, ClassAttribute>> objAttributes)
        {
            for (int i = 0; i < objAttributes.Count; i++)
            {
                ObjectAttribute objAttribute = objAttributes[i].Item1;
                DisplayAttribute(objAttribute);
            }
        }
        private void DisplayAttributes(List<ObjectAttribute> objAttributes)
        {
            for (int i = 0; i < objAttributes.Count; ++i)
            {
                DisplayAttribute(objAttributes[i]);
            }
        }

        private void DisplayAttribute(ObjectAttribute attribute)
        {
            string attrname = null;
            string attrval = null;
            StringUtils.GetAttributeNameAndValue(attribute, out attrname, out attrval);
            System.Console.WriteLine(attrname + "=" + attrval);
        }

        private void RemoveAttribute(List<Tuple<ObjectAttribute, ClassAttribute>> objectAttributes, ulong removeType)
        {
            for (int i = 0; i < objectAttributes.Count; i++)
            {
                ObjectAttribute objectAttribute = objectAttributes[i].Item1;
                ClassAttribute classAttribute = objectAttributes[i].Item2;

                if (objectAttribute.Type == removeType)
                {
                    objectAttributes.Remove(objectAttributes[i]);   // Remove the attribute
                    return;
                }
            }
        }

        private void PKCS12FilenameTextBox_TextChanged(object sender, EventArgs e)
        {
            updateButtonStatus();
        }

        private void PKCS12PasswordTextBox_TextChanged(object sender, EventArgs e)
        {
            updateButtonStatus();
        }

        private void updateButtonStatus()
        {
            if (PKCS12FilenameTextBox.Text.Length > 0 && PKCS12PasswordTextBox.Text.Length > 0)
            {
                PKCS12OKButton.Enabled = true;
            } else
            {
                PKCS12OKButton.Enabled = false;
            }
        }

        private void PKCS12ImportKeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
                PKCS12OKButton.PerformClick();
        }
    }
}
