using System.Runtime.InteropServices;
using KerckhoffsLabs.Security.Cryptography.Pkcs11.Common;

namespace KerckhoffsLabs.Security.Cryptography.Pkcs11.HighLevel;

/// <summary>
    /// Flags that define the type of session
    /// </summary>
    public class SessionFlags
    {
        /// <summary>
        /// Bit flags that define the type of session
        /// </summary>
        protected NativeCULong _flags;

        /// <summary>
        /// Bit flags that define the type of session
        /// </summary>
        public ulong Flags
        {
            get
            {
                return (ulong)_flags;
            }
        }

        /// <summary>
        /// True if the session is read/write; false if the session is read-only
        /// </summary>
        public bool RwSession
        {
            get
            {
                return new NativeCULong(_flags.Value & CKF.CKF_RW_SESSION.Value).Value == CKF.CKF_RW_SESSION.Value;
            }
        }

        /// <summary>
        /// This flag is provided for backward compatibility, and should always be set to true
        /// </summary>
        public bool SerialSession
        {
            get
            {
                return new NativeCULong(_flags.Value & CKF.CKF_SERIAL_SESSION.Value).Value == CKF.CKF_SERIAL_SESSION.Value;
            }
        }

        /// <summary>
        /// Initializes new instance of SessionFlags class
        /// </summary>
        /// <param name="flags">Bit flags that define the type of session</param>
        protected internal SessionFlags(NativeCULong flags)
        {
            _flags = flags;
        }
    }