#if defined(__GNUC__)
#define MUST_USE_STRUCT __attribute__((warn_unused))
#define MUST_USE_RES __attribute__((warn_unused_result))
#else
#define MUST_USE_STRUCT
#define MUST_USE_RES
#endif
#if defined(__clang__)
#define NONNULL_PTR _Nonnull
#else
#define NONNULL_PTR
#endif
struct nativeCounterpartyCommitmentSecretsOpaque;
typedef struct nativeCounterpartyCommitmentSecretsOpaque LDKnativeCounterpartyCommitmentSecrets;
struct nativeTxCreationKeysOpaque;
typedef struct nativeTxCreationKeysOpaque LDKnativeTxCreationKeys;
struct nativeChannelPublicKeysOpaque;
typedef struct nativeChannelPublicKeysOpaque LDKnativeChannelPublicKeys;
struct nativeHTLCOutputInCommitmentOpaque;
typedef struct nativeHTLCOutputInCommitmentOpaque LDKnativeHTLCOutputInCommitment;
struct nativeChannelTransactionParametersOpaque;
typedef struct nativeChannelTransactionParametersOpaque LDKnativeChannelTransactionParameters;
struct nativeCounterpartyChannelTransactionParametersOpaque;
typedef struct nativeCounterpartyChannelTransactionParametersOpaque LDKnativeCounterpartyChannelTransactionParameters;
struct nativeDirectedChannelTransactionParametersOpaque;
typedef struct nativeDirectedChannelTransactionParametersOpaque LDKnativeDirectedChannelTransactionParameters;
struct nativeHolderCommitmentTransactionOpaque;
typedef struct nativeHolderCommitmentTransactionOpaque LDKnativeHolderCommitmentTransaction;
struct nativeBuiltCommitmentTransactionOpaque;
typedef struct nativeBuiltCommitmentTransactionOpaque LDKnativeBuiltCommitmentTransaction;
struct nativeClosingTransactionOpaque;
typedef struct nativeClosingTransactionOpaque LDKnativeClosingTransaction;
struct nativeTrustedClosingTransactionOpaque;
typedef struct nativeTrustedClosingTransactionOpaque LDKnativeTrustedClosingTransaction;
struct nativeCommitmentTransactionOpaque;
typedef struct nativeCommitmentTransactionOpaque LDKnativeCommitmentTransaction;
struct nativeTrustedCommitmentTransactionOpaque;
typedef struct nativeTrustedCommitmentTransactionOpaque LDKnativeTrustedCommitmentTransaction;
struct nativeShutdownScriptOpaque;
typedef struct nativeShutdownScriptOpaque LDKnativeShutdownScript;
struct nativeInvalidShutdownScriptOpaque;
typedef struct nativeInvalidShutdownScriptOpaque LDKnativeInvalidShutdownScript;
struct nativeBackgroundProcessorOpaque;
typedef struct nativeBackgroundProcessorOpaque LDKnativeBackgroundProcessor;
struct nativeRouteHopOpaque;
typedef struct nativeRouteHopOpaque LDKnativeRouteHop;
struct nativeRouteOpaque;
typedef struct nativeRouteOpaque LDKnativeRoute;
struct nativeRouteParametersOpaque;
typedef struct nativeRouteParametersOpaque LDKnativeRouteParameters;
struct nativePaymentParametersOpaque;
typedef struct nativePaymentParametersOpaque LDKnativePaymentParameters;
struct nativeRouteHintOpaque;
typedef struct nativeRouteHintOpaque LDKnativeRouteHint;
struct nativeRouteHintHopOpaque;
typedef struct nativeRouteHintHopOpaque LDKnativeRouteHintHop;
struct nativeBestBlockOpaque;
typedef struct nativeBestBlockOpaque LDKnativeBestBlock;
struct nativeWatchedOutputOpaque;
typedef struct nativeWatchedOutputOpaque LDKnativeWatchedOutput;
struct nativeMultiThreadedLockableScoreOpaque;
typedef struct nativeMultiThreadedLockableScoreOpaque LDKnativeMultiThreadedLockableScore;
struct nativeChannelUsageOpaque;
typedef struct nativeChannelUsageOpaque LDKnativeChannelUsage;
struct nativeFixedPenaltyScorerOpaque;
typedef struct nativeFixedPenaltyScorerOpaque LDKnativeFixedPenaltyScorer;
struct nativeProbabilisticScorerOpaque;
typedef struct nativeProbabilisticScorerOpaque LDKnativeProbabilisticScorer;
struct nativeProbabilisticScoringParametersOpaque;
typedef struct nativeProbabilisticScoringParametersOpaque LDKnativeProbabilisticScoringParameters;
struct nativeInitFeaturesOpaque;
typedef struct nativeInitFeaturesOpaque LDKnativeInitFeatures;
struct nativeNodeFeaturesOpaque;
typedef struct nativeNodeFeaturesOpaque LDKnativeNodeFeatures;
struct nativeChannelFeaturesOpaque;
typedef struct nativeChannelFeaturesOpaque LDKnativeChannelFeatures;
struct nativeInvoiceFeaturesOpaque;
typedef struct nativeInvoiceFeaturesOpaque LDKnativeInvoiceFeatures;
struct nativeChannelTypeFeaturesOpaque;
typedef struct nativeChannelTypeFeaturesOpaque LDKnativeChannelTypeFeatures;
struct nativeNodeIdOpaque;
typedef struct nativeNodeIdOpaque LDKnativeNodeId;
struct nativeNetworkGraphOpaque;
typedef struct nativeNetworkGraphOpaque LDKnativeNetworkGraph;
struct nativeReadOnlyNetworkGraphOpaque;
typedef struct nativeReadOnlyNetworkGraphOpaque LDKnativeReadOnlyNetworkGraph;
struct nativeP2PGossipSyncOpaque;
typedef struct nativeP2PGossipSyncOpaque LDKnativeP2PGossipSync;
struct nativeChannelUpdateInfoOpaque;
typedef struct nativeChannelUpdateInfoOpaque LDKnativeChannelUpdateInfo;
struct nativeChannelInfoOpaque;
typedef struct nativeChannelInfoOpaque LDKnativeChannelInfo;
struct nativeDirectedChannelInfoOpaque;
typedef struct nativeDirectedChannelInfoOpaque LDKnativeDirectedChannelInfo;
struct nativeRoutingFeesOpaque;
typedef struct nativeRoutingFeesOpaque LDKnativeRoutingFees;
struct nativeNodeAnnouncementInfoOpaque;
typedef struct nativeNodeAnnouncementInfoOpaque LDKnativeNodeAnnouncementInfo;
struct nativeNodeAliasOpaque;
typedef struct nativeNodeAliasOpaque LDKnativeNodeAlias;
struct nativeNodeInfoOpaque;
typedef struct nativeNodeInfoOpaque LDKnativeNodeInfo;
struct nativeDelayedPaymentOutputDescriptorOpaque;
typedef struct nativeDelayedPaymentOutputDescriptorOpaque LDKnativeDelayedPaymentOutputDescriptor;
struct nativeStaticPaymentOutputDescriptorOpaque;
typedef struct nativeStaticPaymentOutputDescriptorOpaque LDKnativeStaticPaymentOutputDescriptor;
struct LDKBaseSign;
struct nativeInMemorySignerOpaque;
typedef struct nativeInMemorySignerOpaque LDKnativeInMemorySigner;
struct nativeKeysManagerOpaque;
typedef struct nativeKeysManagerOpaque LDKnativeKeysManager;
struct nativePhantomKeysManagerOpaque;
typedef struct nativePhantomKeysManagerOpaque LDKnativePhantomKeysManager;
struct nativeFilesystemPersisterOpaque;
typedef struct nativeFilesystemPersisterOpaque LDKnativeFilesystemPersister;
struct nativeChannelManagerOpaque;
typedef struct nativeChannelManagerOpaque LDKnativeChannelManager;
struct nativeChainParametersOpaque;
typedef struct nativeChainParametersOpaque LDKnativeChainParameters;
struct nativeCounterpartyForwardingInfoOpaque;
typedef struct nativeCounterpartyForwardingInfoOpaque LDKnativeCounterpartyForwardingInfo;
struct nativeChannelCounterpartyOpaque;
typedef struct nativeChannelCounterpartyOpaque LDKnativeChannelCounterparty;
struct nativeChannelDetailsOpaque;
typedef struct nativeChannelDetailsOpaque LDKnativeChannelDetails;
struct nativePhantomRouteHintsOpaque;
typedef struct nativePhantomRouteHintsOpaque LDKnativePhantomRouteHints;
struct nativeChannelManagerReadArgsOpaque;
typedef struct nativeChannelManagerReadArgsOpaque LDKnativeChannelManagerReadArgs;
struct nativeChannelHandshakeConfigOpaque;
typedef struct nativeChannelHandshakeConfigOpaque LDKnativeChannelHandshakeConfig;
struct nativeChannelHandshakeLimitsOpaque;
typedef struct nativeChannelHandshakeLimitsOpaque LDKnativeChannelHandshakeLimits;
struct nativeChannelConfigOpaque;
typedef struct nativeChannelConfigOpaque LDKnativeChannelConfig;
struct nativeUserConfigOpaque;
typedef struct nativeUserConfigOpaque LDKnativeUserConfig;
struct nativeBigSizeOpaque;
typedef struct nativeBigSizeOpaque LDKnativeBigSize;
struct nativeOutPointOpaque;
typedef struct nativeOutPointOpaque LDKnativeOutPoint;
struct nativeInvoicePayerOpaque;
typedef struct nativeInvoicePayerOpaque LDKnativeInvoicePayer;
struct nativeInvoiceOpaque;
typedef struct nativeInvoiceOpaque LDKnativeInvoice;
struct nativeSignedRawInvoiceOpaque;
typedef struct nativeSignedRawInvoiceOpaque LDKnativeSignedRawInvoice;
struct nativeRawInvoiceOpaque;
typedef struct nativeRawInvoiceOpaque LDKnativeRawInvoice;
struct nativeRawDataPartOpaque;
typedef struct nativeRawDataPartOpaque LDKnativeRawDataPart;
struct nativePositiveTimestampOpaque;
typedef struct nativePositiveTimestampOpaque LDKnativePositiveTimestamp;
struct nativeSha256Opaque;
typedef struct nativeSha256Opaque LDKnativeSha256;
struct nativeDescriptionOpaque;
typedef struct nativeDescriptionOpaque LDKnativeDescription;
struct nativePayeePubKeyOpaque;
typedef struct nativePayeePubKeyOpaque LDKnativePayeePubKey;
struct nativeExpiryTimeOpaque;
typedef struct nativeExpiryTimeOpaque LDKnativeExpiryTime;
struct nativeMinFinalCltvExpiryOpaque;
typedef struct nativeMinFinalCltvExpiryOpaque LDKnativeMinFinalCltvExpiry;
struct nativeInvoiceSignatureOpaque;
typedef struct nativeInvoiceSignatureOpaque LDKnativeInvoiceSignature;
struct nativePrivateRouteOpaque;
typedef struct nativePrivateRouteOpaque LDKnativePrivateRoute;
struct nativeChannelMonitorUpdateOpaque;
typedef struct nativeChannelMonitorUpdateOpaque LDKnativeChannelMonitorUpdate;
struct nativeHTLCUpdateOpaque;
typedef struct nativeHTLCUpdateOpaque LDKnativeHTLCUpdate;
struct nativeChannelMonitorOpaque;
typedef struct nativeChannelMonitorOpaque LDKnativeChannelMonitor;
struct nativeExpandedKeyOpaque;
typedef struct nativeExpandedKeyOpaque LDKnativeExpandedKey;
struct nativeIgnoringMessageHandlerOpaque;
typedef struct nativeIgnoringMessageHandlerOpaque LDKnativeIgnoringMessageHandler;
struct nativeErroringMessageHandlerOpaque;
typedef struct nativeErroringMessageHandlerOpaque LDKnativeErroringMessageHandler;
struct nativeMessageHandlerOpaque;
typedef struct nativeMessageHandlerOpaque LDKnativeMessageHandler;
struct nativePeerHandleErrorOpaque;
typedef struct nativePeerHandleErrorOpaque LDKnativePeerHandleError;
struct nativePeerManagerOpaque;
typedef struct nativePeerManagerOpaque LDKnativePeerManager;
struct nativeRapidGossipSyncOpaque;
typedef struct nativeRapidGossipSyncOpaque LDKnativeRapidGossipSync;
struct nativeDecodeErrorOpaque;
typedef struct nativeDecodeErrorOpaque LDKnativeDecodeError;
struct nativeInitOpaque;
typedef struct nativeInitOpaque LDKnativeInit;
struct nativeErrorMessageOpaque;
typedef struct nativeErrorMessageOpaque LDKnativeErrorMessage;
struct nativeWarningMessageOpaque;
typedef struct nativeWarningMessageOpaque LDKnativeWarningMessage;
struct nativePingOpaque;
typedef struct nativePingOpaque LDKnativePing;
struct nativePongOpaque;
typedef struct nativePongOpaque LDKnativePong;
struct nativeOpenChannelOpaque;
typedef struct nativeOpenChannelOpaque LDKnativeOpenChannel;
struct nativeAcceptChannelOpaque;
typedef struct nativeAcceptChannelOpaque LDKnativeAcceptChannel;
struct nativeFundingCreatedOpaque;
typedef struct nativeFundingCreatedOpaque LDKnativeFundingCreated;
struct nativeFundingSignedOpaque;
typedef struct nativeFundingSignedOpaque LDKnativeFundingSigned;
struct nativeChannelReadyOpaque;
typedef struct nativeChannelReadyOpaque LDKnativeChannelReady;
struct nativeShutdownOpaque;
typedef struct nativeShutdownOpaque LDKnativeShutdown;
struct nativeClosingSignedFeeRangeOpaque;
typedef struct nativeClosingSignedFeeRangeOpaque LDKnativeClosingSignedFeeRange;
struct nativeClosingSignedOpaque;
typedef struct nativeClosingSignedOpaque LDKnativeClosingSigned;
struct nativeUpdateAddHTLCOpaque;
typedef struct nativeUpdateAddHTLCOpaque LDKnativeUpdateAddHTLC;
struct nativeUpdateFulfillHTLCOpaque;
typedef struct nativeUpdateFulfillHTLCOpaque LDKnativeUpdateFulfillHTLC;
struct nativeUpdateFailHTLCOpaque;
typedef struct nativeUpdateFailHTLCOpaque LDKnativeUpdateFailHTLC;
struct nativeUpdateFailMalformedHTLCOpaque;
typedef struct nativeUpdateFailMalformedHTLCOpaque LDKnativeUpdateFailMalformedHTLC;
struct nativeCommitmentSignedOpaque;
typedef struct nativeCommitmentSignedOpaque LDKnativeCommitmentSigned;
struct nativeRevokeAndACKOpaque;
typedef struct nativeRevokeAndACKOpaque LDKnativeRevokeAndACK;
struct nativeUpdateFeeOpaque;
typedef struct nativeUpdateFeeOpaque LDKnativeUpdateFee;
struct nativeDataLossProtectOpaque;
typedef struct nativeDataLossProtectOpaque LDKnativeDataLossProtect;
struct nativeChannelReestablishOpaque;
typedef struct nativeChannelReestablishOpaque LDKnativeChannelReestablish;
struct nativeAnnouncementSignaturesOpaque;
typedef struct nativeAnnouncementSignaturesOpaque LDKnativeAnnouncementSignatures;
struct nativeUnsignedNodeAnnouncementOpaque;
typedef struct nativeUnsignedNodeAnnouncementOpaque LDKnativeUnsignedNodeAnnouncement;
struct nativeNodeAnnouncementOpaque;
typedef struct nativeNodeAnnouncementOpaque LDKnativeNodeAnnouncement;
struct nativeUnsignedChannelAnnouncementOpaque;
typedef struct nativeUnsignedChannelAnnouncementOpaque LDKnativeUnsignedChannelAnnouncement;
struct nativeChannelAnnouncementOpaque;
typedef struct nativeChannelAnnouncementOpaque LDKnativeChannelAnnouncement;
struct nativeUnsignedChannelUpdateOpaque;
typedef struct nativeUnsignedChannelUpdateOpaque LDKnativeUnsignedChannelUpdate;
struct nativeChannelUpdateOpaque;
typedef struct nativeChannelUpdateOpaque LDKnativeChannelUpdate;
struct nativeQueryChannelRangeOpaque;
typedef struct nativeQueryChannelRangeOpaque LDKnativeQueryChannelRange;
struct nativeReplyChannelRangeOpaque;
typedef struct nativeReplyChannelRangeOpaque LDKnativeReplyChannelRange;
struct nativeQueryShortChannelIdsOpaque;
typedef struct nativeQueryShortChannelIdsOpaque LDKnativeQueryShortChannelIds;
struct nativeReplyShortChannelIdsEndOpaque;
typedef struct nativeReplyShortChannelIdsEndOpaque LDKnativeReplyShortChannelIdsEnd;
struct nativeGossipTimestampFilterOpaque;
typedef struct nativeGossipTimestampFilterOpaque LDKnativeGossipTimestampFilter;
struct nativeLightningErrorOpaque;
typedef struct nativeLightningErrorOpaque LDKnativeLightningError;
struct nativeCommitmentUpdateOpaque;
typedef struct nativeCommitmentUpdateOpaque LDKnativeCommitmentUpdate;
struct nativeDefaultRouterOpaque;
typedef struct nativeDefaultRouterOpaque LDKnativeDefaultRouter;
struct nativeRecordOpaque;
typedef struct nativeRecordOpaque LDKnativeRecord;
struct nativeMonitorUpdateIdOpaque;
typedef struct nativeMonitorUpdateIdOpaque LDKnativeMonitorUpdateId;
struct nativeLockedChannelMonitorOpaque;
typedef struct nativeLockedChannelMonitorOpaque LDKnativeLockedChannelMonitor;
struct nativeChainMonitorOpaque;
typedef struct nativeChainMonitorOpaque LDKnativeChainMonitor;
