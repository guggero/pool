// Code generated by MockGen. DO NOT EDIT.
// Source: account/interfaces.go

// Package account is a generated GoMock package.
package account

import (
	context "context"
	reflect "reflect"

	v2 "github.com/btcsuite/btcd/btcec/v2"
	btcutil "github.com/btcsuite/btcd/btcutil"
	wire "github.com/btcsuite/btcd/wire"
	wtxmgr "github.com/btcsuite/btcwallet/wtxmgr"
	gomock "github.com/golang/mock/gomock"
	lndclient "github.com/lightninglabs/lndclient"
	terms "github.com/lightninglabs/pool/terms"
	chainntnfs "github.com/lightningnetwork/lnd/chainntnfs"
	keychain "github.com/lightningnetwork/lnd/keychain"
	chainfee "github.com/lightningnetwork/lnd/lnwallet/chainfee"
)

// MockStore is a mock of Store interface.
type MockStore struct {
	ctrl     *gomock.Controller
	recorder *MockStoreMockRecorder
}

// MockStoreMockRecorder is the mock recorder for MockStore.
type MockStoreMockRecorder struct {
	mock *MockStore
}

// NewMockStore creates a new mock instance.
func NewMockStore(ctrl *gomock.Controller) *MockStore {
	mock := &MockStore{ctrl: ctrl}
	mock.recorder = &MockStoreMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStore) EXPECT() *MockStoreMockRecorder {
	return m.recorder
}

// Account mocks base method.
func (m *MockStore) Account(arg0 *v2.PublicKey) (*Account, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Account", arg0)
	ret0, _ := ret[0].(*Account)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Account indicates an expected call of Account.
func (mr *MockStoreMockRecorder) Account(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Account", reflect.TypeOf((*MockStore)(nil).Account), arg0)
}

// Accounts mocks base method.
func (m *MockStore) Accounts() ([]*Account, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Accounts")
	ret0, _ := ret[0].([]*Account)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Accounts indicates an expected call of Accounts.
func (mr *MockStoreMockRecorder) Accounts() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Accounts", reflect.TypeOf((*MockStore)(nil).Accounts))
}

// AddAccount mocks base method.
func (m *MockStore) AddAccount(arg0 *Account) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddAccount", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddAccount indicates an expected call of AddAccount.
func (mr *MockStoreMockRecorder) AddAccount(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddAccount", reflect.TypeOf((*MockStore)(nil).AddAccount), arg0)
}

// LockID mocks base method.
func (m *MockStore) LockID() (wtxmgr.LockID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "LockID")
	ret0, _ := ret[0].(wtxmgr.LockID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LockID indicates an expected call of LockID.
func (mr *MockStoreMockRecorder) LockID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LockID", reflect.TypeOf((*MockStore)(nil).LockID))
}

// MarkBatchComplete mocks base method.
func (m *MockStore) MarkBatchComplete() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MarkBatchComplete")
	ret0, _ := ret[0].(error)
	return ret0
}

// MarkBatchComplete indicates an expected call of MarkBatchComplete.
func (mr *MockStoreMockRecorder) MarkBatchComplete() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MarkBatchComplete", reflect.TypeOf((*MockStore)(nil).MarkBatchComplete))
}

// PendingBatch mocks base method.
func (m *MockStore) PendingBatch() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PendingBatch")
	ret0, _ := ret[0].(error)
	return ret0
}

// PendingBatch indicates an expected call of PendingBatch.
func (mr *MockStoreMockRecorder) PendingBatch() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PendingBatch", reflect.TypeOf((*MockStore)(nil).PendingBatch))
}

// UpdateAccount mocks base method.
func (m *MockStore) UpdateAccount(arg0 *Account, arg1 ...Modifier) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "UpdateAccount", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateAccount indicates an expected call of UpdateAccount.
func (mr *MockStoreMockRecorder) UpdateAccount(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateAccount", reflect.TypeOf((*MockStore)(nil).UpdateAccount), varargs...)
}

// MockAuctioneer is a mock of Auctioneer interface.
type MockAuctioneer struct {
	ctrl     *gomock.Controller
	recorder *MockAuctioneerMockRecorder
}

// MockAuctioneerMockRecorder is the mock recorder for MockAuctioneer.
type MockAuctioneerMockRecorder struct {
	mock *MockAuctioneer
}

// NewMockAuctioneer creates a new mock instance.
func NewMockAuctioneer(ctrl *gomock.Controller) *MockAuctioneer {
	mock := &MockAuctioneer{ctrl: ctrl}
	mock.recorder = &MockAuctioneerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuctioneer) EXPECT() *MockAuctioneerMockRecorder {
	return m.recorder
}

// InitAccount mocks base method.
func (m *MockAuctioneer) InitAccount(arg0 context.Context, arg1 *Account) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitAccount", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// InitAccount indicates an expected call of InitAccount.
func (mr *MockAuctioneerMockRecorder) InitAccount(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitAccount", reflect.TypeOf((*MockAuctioneer)(nil).InitAccount), arg0, arg1)
}

// ModifyAccount mocks base method.
func (m *MockAuctioneer) ModifyAccount(ctx context.Context, acct *Account, inputs []*wire.TxIn, outputs []*wire.TxOut, modifiers []Modifier, traderNonces []byte, previousOutputs []*wire.TxOut) ([]byte, []byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ModifyAccount", ctx, acct, inputs, outputs, modifiers, traderNonces, previousOutputs)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].([]byte)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ModifyAccount indicates an expected call of ModifyAccount.
func (mr *MockAuctioneerMockRecorder) ModifyAccount(ctx, acct, inputs, outputs, modifiers, traderNonces, previousOutputs interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ModifyAccount", reflect.TypeOf((*MockAuctioneer)(nil).ModifyAccount), ctx, acct, inputs, outputs, modifiers, traderNonces, previousOutputs)
}

// ReserveAccount mocks base method.
func (m *MockAuctioneer) ReserveAccount(arg0 context.Context, arg1 btcutil.Amount, arg2 uint32, arg3 *v2.PublicKey, arg4 Version) (*Reservation, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReserveAccount", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*Reservation)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReserveAccount indicates an expected call of ReserveAccount.
func (mr *MockAuctioneerMockRecorder) ReserveAccount(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReserveAccount", reflect.TypeOf((*MockAuctioneer)(nil).ReserveAccount), arg0, arg1, arg2, arg3, arg4)
}

// StartAccountSubscription mocks base method.
func (m *MockAuctioneer) StartAccountSubscription(arg0 context.Context, arg1 *keychain.KeyDescriptor) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "StartAccountSubscription", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// StartAccountSubscription indicates an expected call of StartAccountSubscription.
func (mr *MockAuctioneerMockRecorder) StartAccountSubscription(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StartAccountSubscription", reflect.TypeOf((*MockAuctioneer)(nil).StartAccountSubscription), arg0, arg1)
}

// Terms mocks base method.
func (m *MockAuctioneer) Terms(ctx context.Context) (*terms.AuctioneerTerms, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Terms", ctx)
	ret0, _ := ret[0].(*terms.AuctioneerTerms)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Terms indicates an expected call of Terms.
func (mr *MockAuctioneerMockRecorder) Terms(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Terms", reflect.TypeOf((*MockAuctioneer)(nil).Terms), ctx)
}

// MockTxSource is a mock of TxSource interface.
type MockTxSource struct {
	ctrl     *gomock.Controller
	recorder *MockTxSourceMockRecorder
}

// MockTxSourceMockRecorder is the mock recorder for MockTxSource.
type MockTxSourceMockRecorder struct {
	mock *MockTxSource
}

// NewMockTxSource creates a new mock instance.
func NewMockTxSource(ctrl *gomock.Controller) *MockTxSource {
	mock := &MockTxSource{ctrl: ctrl}
	mock.recorder = &MockTxSourceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTxSource) EXPECT() *MockTxSourceMockRecorder {
	return m.recorder
}

// ListTransactions mocks base method.
func (m *MockTxSource) ListTransactions(ctx context.Context, startHeight, endHeight int32, opts ...lndclient.ListTransactionsOption) ([]lndclient.Transaction, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{ctx, startHeight, endHeight}
	for _, a := range opts {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "ListTransactions", varargs...)
	ret0, _ := ret[0].([]lndclient.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListTransactions indicates an expected call of ListTransactions.
func (mr *MockTxSourceMockRecorder) ListTransactions(ctx, startHeight, endHeight interface{}, opts ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{ctx, startHeight, endHeight}, opts...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListTransactions", reflect.TypeOf((*MockTxSource)(nil).ListTransactions), varargs...)
}

// MockTxFeeEstimator is a mock of TxFeeEstimator interface.
type MockTxFeeEstimator struct {
	ctrl     *gomock.Controller
	recorder *MockTxFeeEstimatorMockRecorder
}

// MockTxFeeEstimatorMockRecorder is the mock recorder for MockTxFeeEstimator.
type MockTxFeeEstimatorMockRecorder struct {
	mock *MockTxFeeEstimator
}

// NewMockTxFeeEstimator creates a new mock instance.
func NewMockTxFeeEstimator(ctrl *gomock.Controller) *MockTxFeeEstimator {
	mock := &MockTxFeeEstimator{ctrl: ctrl}
	mock.recorder = &MockTxFeeEstimatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTxFeeEstimator) EXPECT() *MockTxFeeEstimatorMockRecorder {
	return m.recorder
}

// EstimateFeeToP2WSH mocks base method.
func (m *MockTxFeeEstimator) EstimateFeeToP2WSH(ctx context.Context, amt btcutil.Amount, confTarget int32) (btcutil.Amount, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "EstimateFeeToP2WSH", ctx, amt, confTarget)
	ret0, _ := ret[0].(btcutil.Amount)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// EstimateFeeToP2WSH indicates an expected call of EstimateFeeToP2WSH.
func (mr *MockTxFeeEstimatorMockRecorder) EstimateFeeToP2WSH(ctx, amt, confTarget interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "EstimateFeeToP2WSH", reflect.TypeOf((*MockTxFeeEstimator)(nil).EstimateFeeToP2WSH), ctx, amt, confTarget)
}

// MockFeeExpr is a mock of FeeExpr interface.
type MockFeeExpr struct {
	ctrl     *gomock.Controller
	recorder *MockFeeExprMockRecorder
}

// MockFeeExprMockRecorder is the mock recorder for MockFeeExpr.
type MockFeeExprMockRecorder struct {
	mock *MockFeeExpr
}

// NewMockFeeExpr creates a new mock instance.
func NewMockFeeExpr(ctrl *gomock.Controller) *MockFeeExpr {
	mock := &MockFeeExpr{ctrl: ctrl}
	mock.recorder = &MockFeeExprMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockFeeExpr) EXPECT() *MockFeeExprMockRecorder {
	return m.recorder
}

// CloseOutputs mocks base method.
func (m *MockFeeExpr) CloseOutputs(arg0 btcutil.Amount, arg1 witnessType) ([]*wire.TxOut, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseOutputs", arg0, arg1)
	ret0, _ := ret[0].([]*wire.TxOut)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CloseOutputs indicates an expected call of CloseOutputs.
func (mr *MockFeeExprMockRecorder) CloseOutputs(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseOutputs", reflect.TypeOf((*MockFeeExpr)(nil).CloseOutputs), arg0, arg1)
}

// MockManager is a mock of Manager interface.
type MockManager struct {
	ctrl     *gomock.Controller
	recorder *MockManagerMockRecorder
}

// MockManagerMockRecorder is the mock recorder for MockManager.
type MockManagerMockRecorder struct {
	mock *MockManager
}

// NewMockManager creates a new mock instance.
func NewMockManager(ctrl *gomock.Controller) *MockManager {
	mock := &MockManager{ctrl: ctrl}
	mock.recorder = &MockManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockManager) EXPECT() *MockManagerMockRecorder {
	return m.recorder
}

// BumpAccountFee mocks base method.
func (m *MockManager) BumpAccountFee(ctx context.Context, traderKey *v2.PublicKey, newFeeRate chainfee.SatPerKWeight) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BumpAccountFee", ctx, traderKey, newFeeRate)
	ret0, _ := ret[0].(error)
	return ret0
}

// BumpAccountFee indicates an expected call of BumpAccountFee.
func (mr *MockManagerMockRecorder) BumpAccountFee(ctx, traderKey, newFeeRate interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BumpAccountFee", reflect.TypeOf((*MockManager)(nil).BumpAccountFee), ctx, traderKey, newFeeRate)
}

// CloseAccount mocks base method.
func (m *MockManager) CloseAccount(ctx context.Context, traderKey *v2.PublicKey, feeExpr FeeExpr, bestHeight uint32) (*wire.MsgTx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CloseAccount", ctx, traderKey, feeExpr, bestHeight)
	ret0, _ := ret[0].(*wire.MsgTx)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CloseAccount indicates an expected call of CloseAccount.
func (mr *MockManagerMockRecorder) CloseAccount(ctx, traderKey, feeExpr, bestHeight interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseAccount", reflect.TypeOf((*MockManager)(nil).CloseAccount), ctx, traderKey, feeExpr, bestHeight)
}

// DepositAccount mocks base method.
func (m *MockManager) DepositAccount(ctx context.Context, traderKey *v2.PublicKey, depositAmount btcutil.Amount, feeRate chainfee.SatPerKWeight, bestHeight, expiryHeight uint32, newVersion Version) (*Account, *wire.MsgTx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DepositAccount", ctx, traderKey, depositAmount, feeRate, bestHeight, expiryHeight, newVersion)
	ret0, _ := ret[0].(*Account)
	ret1, _ := ret[1].(*wire.MsgTx)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// DepositAccount indicates an expected call of DepositAccount.
func (mr *MockManagerMockRecorder) DepositAccount(ctx, traderKey, depositAmount, feeRate, bestHeight, expiryHeight, newVersion interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DepositAccount", reflect.TypeOf((*MockManager)(nil).DepositAccount), ctx, traderKey, depositAmount, feeRate, bestHeight, expiryHeight, newVersion)
}

// HandleAccountConf mocks base method.
func (m *MockManager) HandleAccountConf(traderKey *v2.PublicKey, confDetails *chainntnfs.TxConfirmation) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleAccountConf", traderKey, confDetails)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleAccountConf indicates an expected call of HandleAccountConf.
func (mr *MockManagerMockRecorder) HandleAccountConf(traderKey, confDetails interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleAccountConf", reflect.TypeOf((*MockManager)(nil).HandleAccountConf), traderKey, confDetails)
}

// HandleAccountExpiry mocks base method.
func (m *MockManager) HandleAccountExpiry(traderKey *v2.PublicKey, height uint32) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleAccountExpiry", traderKey, height)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleAccountExpiry indicates an expected call of HandleAccountExpiry.
func (mr *MockManagerMockRecorder) HandleAccountExpiry(traderKey, height interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleAccountExpiry", reflect.TypeOf((*MockManager)(nil).HandleAccountExpiry), traderKey, height)
}

// HandleAccountSpend mocks base method.
func (m *MockManager) HandleAccountSpend(traderKey *v2.PublicKey, spendDetails *chainntnfs.SpendDetail) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "HandleAccountSpend", traderKey, spendDetails)
	ret0, _ := ret[0].(error)
	return ret0
}

// HandleAccountSpend indicates an expected call of HandleAccountSpend.
func (mr *MockManagerMockRecorder) HandleAccountSpend(traderKey, spendDetails interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "HandleAccountSpend", reflect.TypeOf((*MockManager)(nil).HandleAccountSpend), traderKey, spendDetails)
}

// InitAccount mocks base method.
func (m *MockManager) InitAccount(ctx context.Context, value btcutil.Amount, version Version, feeRate chainfee.SatPerKWeight, expiry, bestHeight uint32) (*Account, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InitAccount", ctx, value, version, feeRate, expiry, bestHeight)
	ret0, _ := ret[0].(*Account)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InitAccount indicates an expected call of InitAccount.
func (mr *MockManagerMockRecorder) InitAccount(ctx, value, version, feeRate, expiry, bestHeight interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InitAccount", reflect.TypeOf((*MockManager)(nil).InitAccount), ctx, value, version, feeRate, expiry, bestHeight)
}

// MintAssets mocks base method.
func (m *MockManager) MintAssets(ctx context.Context, traderKey, taroBatchKey *v2.PublicKey, feeRate chainfee.SatPerKWeight, bestHeight uint32, newVersion Version) (*Account, *wire.MsgTx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MintAssets", ctx, traderKey, taroBatchKey, feeRate, bestHeight, newVersion)
	ret0, _ := ret[0].(*Account)
	ret1, _ := ret[1].(*wire.MsgTx)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// MintAssets indicates an expected call of MintAssets.
func (mr *MockManagerMockRecorder) MintAssets(ctx, traderKey, taroBatchKey, feeRate, bestHeight, newVersion interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MintAssets", reflect.TypeOf((*MockManager)(nil).MintAssets), ctx, traderKey, taroBatchKey, feeRate, bestHeight, newVersion)
}

// QuoteAccount mocks base method.
func (m *MockManager) QuoteAccount(ctx context.Context, value btcutil.Amount, confTarget uint32) (chainfee.SatPerKWeight, btcutil.Amount, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "QuoteAccount", ctx, value, confTarget)
	ret0, _ := ret[0].(chainfee.SatPerKWeight)
	ret1, _ := ret[1].(btcutil.Amount)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// QuoteAccount indicates an expected call of QuoteAccount.
func (mr *MockManagerMockRecorder) QuoteAccount(ctx, value, confTarget interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QuoteAccount", reflect.TypeOf((*MockManager)(nil).QuoteAccount), ctx, value, confTarget)
}

// RecoverAccount mocks base method.
func (m *MockManager) RecoverAccount(ctx context.Context, account *Account) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RecoverAccount", ctx, account)
	ret0, _ := ret[0].(error)
	return ret0
}

// RecoverAccount indicates an expected call of RecoverAccount.
func (mr *MockManagerMockRecorder) RecoverAccount(ctx, account interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RecoverAccount", reflect.TypeOf((*MockManager)(nil).RecoverAccount), ctx, account)
}

// RenewAccount mocks base method.
func (m *MockManager) RenewAccount(ctx context.Context, traderKey *v2.PublicKey, newExpiry uint32, feeRate chainfee.SatPerKWeight, bestHeight uint32, newVersion Version) (*Account, *wire.MsgTx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RenewAccount", ctx, traderKey, newExpiry, feeRate, bestHeight, newVersion)
	ret0, _ := ret[0].(*Account)
	ret1, _ := ret[1].(*wire.MsgTx)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// RenewAccount indicates an expected call of RenewAccount.
func (mr *MockManagerMockRecorder) RenewAccount(ctx, traderKey, newExpiry, feeRate, bestHeight, newVersion interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RenewAccount", reflect.TypeOf((*MockManager)(nil).RenewAccount), ctx, traderKey, newExpiry, feeRate, bestHeight, newVersion)
}

// Start mocks base method.
func (m *MockManager) Start() error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Start")
	ret0, _ := ret[0].(error)
	return ret0
}

// Start indicates an expected call of Start.
func (mr *MockManagerMockRecorder) Start() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Start", reflect.TypeOf((*MockManager)(nil).Start))
}

// Stop mocks base method.
func (m *MockManager) Stop() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Stop")
}

// Stop indicates an expected call of Stop.
func (mr *MockManagerMockRecorder) Stop() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Stop", reflect.TypeOf((*MockManager)(nil).Stop))
}

// WatchMatchedAccounts mocks base method.
func (m *MockManager) WatchMatchedAccounts(ctx context.Context, matchedAccounts []*v2.PublicKey) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WatchMatchedAccounts", ctx, matchedAccounts)
	ret0, _ := ret[0].(error)
	return ret0
}

// WatchMatchedAccounts indicates an expected call of WatchMatchedAccounts.
func (mr *MockManagerMockRecorder) WatchMatchedAccounts(ctx, matchedAccounts interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WatchMatchedAccounts", reflect.TypeOf((*MockManager)(nil).WatchMatchedAccounts), ctx, matchedAccounts)
}

// WithdrawAccount mocks base method.
func (m *MockManager) WithdrawAccount(ctx context.Context, traderKey *v2.PublicKey, outputs []*wire.TxOut, feeRate chainfee.SatPerKWeight, bestHeight, expiryHeight uint32, newVersion Version) (*Account, *wire.MsgTx, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WithdrawAccount", ctx, traderKey, outputs, feeRate, bestHeight, expiryHeight, newVersion)
	ret0, _ := ret[0].(*Account)
	ret1, _ := ret[1].(*wire.MsgTx)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// WithdrawAccount indicates an expected call of WithdrawAccount.
func (mr *MockManagerMockRecorder) WithdrawAccount(ctx, traderKey, outputs, feeRate, bestHeight, expiryHeight, newVersion interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WithdrawAccount", reflect.TypeOf((*MockManager)(nil).WithdrawAccount), ctx, traderKey, outputs, feeRate, bestHeight, expiryHeight, newVersion)
}
