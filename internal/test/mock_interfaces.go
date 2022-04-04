// Code generated by MockGen. DO NOT EDIT.
// Source: internal/test/interfaces.go

// Package test is a generated GoMock package.
package test

import (
	context "context"
	reflect "reflect"
	time "time"

	btcec "github.com/btcsuite/btcd/btcec/v2"
	btcutil "github.com/btcsuite/btcd/btcutil"
	chainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	wire "github.com/btcsuite/btcd/wire"
	wtxmgr "github.com/btcsuite/btcwallet/wtxmgr"
	gomock "github.com/golang/mock/gomock"
	lndclient "github.com/lightninglabs/lndclient"
	chainntnfs "github.com/lightningnetwork/lnd/chainntnfs"
	input "github.com/lightningnetwork/lnd/input"
	keychain "github.com/lightningnetwork/lnd/keychain"
	walletrpc "github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	lnwallet "github.com/lightningnetwork/lnd/lnwallet"
	chainfee "github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// MockSignerClient is a mock of SignerClient interface.
type MockSignerClient struct {
	ctrl     *gomock.Controller
	recorder *MockSignerClientMockRecorder
}

// MockSignerClientMockRecorder is the mock recorder for MockSignerClient.
type MockSignerClientMockRecorder struct {
	mock *MockSignerClient
}

// NewMockSignerClient creates a new mock instance.
func NewMockSignerClient(ctrl *gomock.Controller) *MockSignerClient {
	mock := &MockSignerClient{ctrl: ctrl}
	mock.recorder = &MockSignerClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSignerClient) EXPECT() *MockSignerClientMockRecorder {
	return m.recorder
}

// ComputeInputScript mocks base method.
func (m *MockSignerClient) ComputeInputScript(ctx context.Context, tx *wire.MsgTx, signDescriptors []*lndclient.SignDescriptor) ([]*input.Script, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ComputeInputScript", ctx, tx, signDescriptors)
	ret0, _ := ret[0].([]*input.Script)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ComputeInputScript indicates an expected call of ComputeInputScript.
func (mr *MockSignerClientMockRecorder) ComputeInputScript(ctx, tx, signDescriptors interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ComputeInputScript", reflect.TypeOf((*MockSignerClient)(nil).ComputeInputScript), ctx, tx, signDescriptors)
}

// DeriveSharedKey mocks base method.
func (m *MockSignerClient) DeriveSharedKey(ctx context.Context, ephemeralPubKey *btcec.PublicKey, keyLocator *keychain.KeyLocator) ([32]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeriveSharedKey", ctx, ephemeralPubKey, keyLocator)
	ret0, _ := ret[0].([32]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeriveSharedKey indicates an expected call of DeriveSharedKey.
func (mr *MockSignerClientMockRecorder) DeriveSharedKey(ctx, ephemeralPubKey, keyLocator interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeriveSharedKey", reflect.TypeOf((*MockSignerClient)(nil).DeriveSharedKey), ctx, ephemeralPubKey, keyLocator)
}

// SignMessage mocks base method.
func (m *MockSignerClient) SignMessage(ctx context.Context, msg []byte, locator keychain.KeyLocator) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignMessage", ctx, msg, locator)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignMessage indicates an expected call of SignMessage.
func (mr *MockSignerClientMockRecorder) SignMessage(ctx, msg, locator interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignMessage", reflect.TypeOf((*MockSignerClient)(nil).SignMessage), ctx, msg, locator)
}

// SignOutputRaw mocks base method.
func (m *MockSignerClient) SignOutputRaw(ctx context.Context, tx *wire.MsgTx, signDescriptors []*lndclient.SignDescriptor, prevOutputs []*wire.TxOut) ([][]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignOutputRaw", ctx, tx, signDescriptors, prevOutputs)
	ret0, _ := ret[0].([][]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SignOutputRaw indicates an expected call of SignOutputRaw.
func (mr *MockSignerClientMockRecorder) SignOutputRaw(ctx, tx, signDescriptors, prevOutputs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignOutputRaw", reflect.TypeOf((*MockSignerClient)(nil).SignOutputRaw), ctx, tx, signDescriptors, prevOutputs)
}

// VerifyMessage mocks base method.
func (m *MockSignerClient) VerifyMessage(ctx context.Context, msg, sig []byte, pubkey [33]byte) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyMessage", ctx, msg, sig, pubkey)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyMessage indicates an expected call of VerifyMessage.
func (mr *MockSignerClientMockRecorder) VerifyMessage(ctx, msg, sig, pubkey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyMessage", reflect.TypeOf((*MockSignerClient)(nil).VerifyMessage), ctx, msg, sig, pubkey)
}

// MockWalletKitClient is a mock of WalletKitClient interface.
type MockWalletKitClient struct {
	ctrl     *gomock.Controller
	recorder *MockWalletKitClientMockRecorder
}

// MockWalletKitClientMockRecorder is the mock recorder for MockWalletKitClient.
type MockWalletKitClientMockRecorder struct {
	mock *MockWalletKitClient
}

// NewMockWalletKitClient creates a new mock instance.
func NewMockWalletKitClient(ctrl *gomock.Controller) *MockWalletKitClient {
	mock := &MockWalletKitClient{ctrl: ctrl}
	mock.recorder = &MockWalletKitClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWalletKitClient) EXPECT() *MockWalletKitClientMockRecorder {
	return m.recorder
}

// BumpFee mocks base method.
func (m *MockWalletKitClient) BumpFee(arg0 context.Context, arg1 wire.OutPoint, arg2 chainfee.SatPerKWeight) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BumpFee", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// BumpFee indicates an expected call of BumpFee.
func (mr *MockWalletKitClientMockRecorder) BumpFee(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BumpFee", reflect.TypeOf((*MockWalletKitClient)(nil).BumpFee), arg0, arg1, arg2)
}

// DeriveKey mocks base method.
func (m *MockWalletKitClient) DeriveKey(ctx context.Context, locator *keychain.KeyLocator) (*keychain.KeyDescriptor, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeriveKey", ctx, locator)
	ret0, _ := ret[0].(*keychain.KeyDescriptor)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeriveKey indicates an expected call of DeriveKey.
func (mr *MockWalletKitClientMockRecorder) DeriveKey(ctx, locator interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeriveKey", reflect.TypeOf((*MockWalletKitClient)(nil).DeriveKey), ctx, locator)
}

// DeriveNextKey mocks base method.
func (m *MockWalletKitClient) DeriveNextKey(ctx context.Context, family int32) (*keychain.KeyDescriptor, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DeriveNextKey", ctx, family)
	ret0, _ := ret[0].(*keychain.KeyDescriptor)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DeriveNextKey indicates an expected call of DeriveNextKey.
func (mr *MockWalletKitClientMockRecorder) DeriveNextKey(ctx, family interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeriveNextKey", reflect.TypeOf((*MockWalletKitClient)(nil).DeriveNextKey), ctx, family)
}

// EstimateFee mocks base method.
func (m *MockWalletKitClient) EstimateFee(ctx context.Context, confTarget int32) (chainfee.SatPerKWeight, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EstimateFee", ctx, confTarget)
	ret0, _ := ret[0].(chainfee.SatPerKWeight)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EstimateFee indicates an expected call of EstimateFee.
func (mr *MockWalletKitClientMockRecorder) EstimateFee(ctx, confTarget interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EstimateFee", reflect.TypeOf((*MockWalletKitClient)(nil).EstimateFee), ctx, confTarget)
}

// LeaseOutput mocks base method.
func (m *MockWalletKitClient) LeaseOutput(ctx context.Context, lockID wtxmgr.LockID, op wire.OutPoint, leaseTime time.Duration) (time.Time, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LeaseOutput", ctx, lockID, op, leaseTime)
	ret0, _ := ret[0].(time.Time)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LeaseOutput indicates an expected call of LeaseOutput.
func (mr *MockWalletKitClientMockRecorder) LeaseOutput(ctx, lockID, op, leaseTime interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LeaseOutput", reflect.TypeOf((*MockWalletKitClient)(nil).LeaseOutput), ctx, lockID, op, leaseTime)
}

// ListAccounts mocks base method.
func (m *MockWalletKitClient) ListAccounts(ctx context.Context, name string, addressType walletrpc.AddressType) ([]*walletrpc.Account, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListAccounts", ctx, name, addressType)
	ret0, _ := ret[0].([]*walletrpc.Account)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListAccounts indicates an expected call of ListAccounts.
func (mr *MockWalletKitClientMockRecorder) ListAccounts(ctx, name, addressType interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListAccounts", reflect.TypeOf((*MockWalletKitClient)(nil).ListAccounts), ctx, name, addressType)
}

// ListSweeps mocks base method.
func (m *MockWalletKitClient) ListSweeps(ctx context.Context) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListSweeps", ctx)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListSweeps indicates an expected call of ListSweeps.
func (mr *MockWalletKitClientMockRecorder) ListSweeps(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListSweeps", reflect.TypeOf((*MockWalletKitClient)(nil).ListSweeps), ctx)
}

// ListUnspent mocks base method.
func (m *MockWalletKitClient) ListUnspent(ctx context.Context, minConfs, maxConfs int32) ([]*lnwallet.Utxo, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListUnspent", ctx, minConfs, maxConfs)
	ret0, _ := ret[0].([]*lnwallet.Utxo)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListUnspent indicates an expected call of ListUnspent.
func (mr *MockWalletKitClientMockRecorder) ListUnspent(ctx, minConfs, maxConfs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListUnspent", reflect.TypeOf((*MockWalletKitClient)(nil).ListUnspent), ctx, minConfs, maxConfs)
}

// NextAddr mocks base method.
func (m *MockWalletKitClient) NextAddr(ctx context.Context) (btcutil.Address, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NextAddr", ctx)
	ret0, _ := ret[0].(btcutil.Address)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NextAddr indicates an expected call of NextAddr.
func (mr *MockWalletKitClientMockRecorder) NextAddr(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NextAddr", reflect.TypeOf((*MockWalletKitClient)(nil).NextAddr), ctx)
}

// PublishTransaction mocks base method.
func (m *MockWalletKitClient) PublishTransaction(ctx context.Context, tx *wire.MsgTx, label string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PublishTransaction", ctx, tx, label)
	ret0, _ := ret[0].(error)
	return ret0
}

// PublishTransaction indicates an expected call of PublishTransaction.
func (mr *MockWalletKitClientMockRecorder) PublishTransaction(ctx, tx, label interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PublishTransaction", reflect.TypeOf((*MockWalletKitClient)(nil).PublishTransaction), ctx, tx, label)
}

// ReleaseOutput mocks base method.
func (m *MockWalletKitClient) ReleaseOutput(ctx context.Context, lockID wtxmgr.LockID, op wire.OutPoint) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReleaseOutput", ctx, lockID, op)
	ret0, _ := ret[0].(error)
	return ret0
}

// ReleaseOutput indicates an expected call of ReleaseOutput.
func (mr *MockWalletKitClientMockRecorder) ReleaseOutput(ctx, lockID, op interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReleaseOutput", reflect.TypeOf((*MockWalletKitClient)(nil).ReleaseOutput), ctx, lockID, op)
}

// SendOutputs mocks base method.
func (m *MockWalletKitClient) SendOutputs(ctx context.Context, outputs []*wire.TxOut, feeRate chainfee.SatPerKWeight, label string) (*wire.MsgTx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendOutputs", ctx, outputs, feeRate, label)
	ret0, _ := ret[0].(*wire.MsgTx)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SendOutputs indicates an expected call of SendOutputs.
func (mr *MockWalletKitClientMockRecorder) SendOutputs(ctx, outputs, feeRate, label interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendOutputs", reflect.TypeOf((*MockWalletKitClient)(nil).SendOutputs), ctx, outputs, feeRate, label)
}

// MockChainNotifierClient is a mock of ChainNotifierClient interface.
type MockChainNotifierClient struct {
	ctrl     *gomock.Controller
	recorder *MockChainNotifierClientMockRecorder
}

// MockChainNotifierClientMockRecorder is the mock recorder for MockChainNotifierClient.
type MockChainNotifierClientMockRecorder struct {
	mock *MockChainNotifierClient
}

// NewMockChainNotifierClient creates a new mock instance.
func NewMockChainNotifierClient(ctrl *gomock.Controller) *MockChainNotifierClient {
	mock := &MockChainNotifierClient{ctrl: ctrl}
	mock.recorder = &MockChainNotifierClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockChainNotifierClient) EXPECT() *MockChainNotifierClientMockRecorder {
	return m.recorder
}

// RegisterBlockEpochNtfn mocks base method.
func (m *MockChainNotifierClient) RegisterBlockEpochNtfn(ctx context.Context) (chan int32, chan error, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterBlockEpochNtfn", ctx)
	ret0, _ := ret[0].(chan int32)
	ret1, _ := ret[1].(chan error)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// RegisterBlockEpochNtfn indicates an expected call of RegisterBlockEpochNtfn.
func (mr *MockChainNotifierClientMockRecorder) RegisterBlockEpochNtfn(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterBlockEpochNtfn", reflect.TypeOf((*MockChainNotifierClient)(nil).RegisterBlockEpochNtfn), ctx)
}

// RegisterConfirmationsNtfn mocks base method.
func (m *MockChainNotifierClient) RegisterConfirmationsNtfn(ctx context.Context, txid *chainhash.Hash, pkScript []byte, numConfs, heightHint int32) (chan *chainntnfs.TxConfirmation, chan error, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterConfirmationsNtfn", ctx, txid, pkScript, numConfs, heightHint)
	ret0, _ := ret[0].(chan *chainntnfs.TxConfirmation)
	ret1, _ := ret[1].(chan error)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// RegisterConfirmationsNtfn indicates an expected call of RegisterConfirmationsNtfn.
func (mr *MockChainNotifierClientMockRecorder) RegisterConfirmationsNtfn(ctx, txid, pkScript, numConfs, heightHint interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterConfirmationsNtfn", reflect.TypeOf((*MockChainNotifierClient)(nil).RegisterConfirmationsNtfn), ctx, txid, pkScript, numConfs, heightHint)
}

// RegisterSpendNtfn mocks base method.
func (m *MockChainNotifierClient) RegisterSpendNtfn(ctx context.Context, outpoint *wire.OutPoint, pkScript []byte, heightHint int32) (chan *chainntnfs.SpendDetail, chan error, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterSpendNtfn", ctx, outpoint, pkScript, heightHint)
	ret0, _ := ret[0].(chan *chainntnfs.SpendDetail)
	ret1, _ := ret[1].(chan error)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// RegisterSpendNtfn indicates an expected call of RegisterSpendNtfn.
func (mr *MockChainNotifierClientMockRecorder) RegisterSpendNtfn(ctx, outpoint, pkScript, heightHint interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterSpendNtfn", reflect.TypeOf((*MockChainNotifierClient)(nil).RegisterSpendNtfn), ctx, outpoint, pkScript, heightHint)
}
