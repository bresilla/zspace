pub const ValidationError = error{
    InvalidName,
    InvalidRootfsPath,
    MissingCommand,
    InvalidCommand,
    InvalidMemoryLimit,
    InvalidCpuLimit,
    InvalidPidsLimit,
    InvalidArgv0,
    InvalidChdir,
    FsActionsRequireMountNamespace,
    InvalidUnsetEnvKey,
    InvalidSetEnvKey,
    InvalidStatusFd,
    InvalidSyncFd,
    InvalidBlockFd,
    InvalidUsernsBlockFd,
    InvalidLockFilePath,
    InvalidNamespaceFd,
    NamespaceAttachConflict,
    InvalidCapability,
    SeccompModeConflict,
    InvalidSeccompFilter,
    InvalidSeccompFilterFd,
    SeccompRequiresNoNewPrivs,
    InvalidFsSource,
    InvalidFsDestination,
    InvalidFsMode,
    InvalidFsSize,
    InvalidFsFd,
    InvalidOverlaySourceKey,
    InvalidOverlayPath,
    DuplicateOverlaySourceKey,
    MissingOverlaySource,
    AssertUserNsDisabledConflict,
    DisableUserNsConflict,
    DisableUserNsRequiresUserNs,
    UserNs2RequiresUserNs,
    IdentityRequiresUserNamespace,
    InvalidHostname,
    AsPid1RequiresPidNamespace,
    SecurityLabelNotSupported,
};

pub const SpawnError = ValidationError || error{
    OutOfMemory,
    SpawnFailed,
    RuntimeInitWarning,
    UserNsNotDisabled,
    UserNsStateUnknown,
};

pub const WaitError = error{
    SessionAlreadyWaited,
    WaitFailed,
};

pub const LaunchError = SpawnError || WaitError;

pub const DoctorError = error{
    DoctorFailed,
};
