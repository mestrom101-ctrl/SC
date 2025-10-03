// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

/**
 * @title GIBToken
 * @dev BEP-20 compliant token for BNB Chain.
 * 
 * Applications:
 * - Increase engagement: Businesses can use this token for customer loyalty and rewards programs.
 * - Raise funds: Supports fundraising and crowdsales by allowing token sales with configurable taxes.
 * - Motivate employees: Enables distribution of tokens as employee incentives, bonuses, or performance rewards.
 * 
 * Features:
 * - Role-based access for governance, oracle, RBS, and treasury.
 * - Configurable buy/sell tax logic for fundraising and treasury management.
 * - Whitelist and governance lists for flexible business logic.
 * - Minting functions for controlled token supply.
 * 
 * BEP-20 Verification:
 * - Implements all required BEP-20 functions and events.
 * - Includes metadata functions: name(), symbol(), decimals(), totalSupply().
 * - Transfer, approve, and allowance functions are present.
 * - Events: Transfer and Approval.
 */

interface IMultiSigWallet {
    function isConfirmed(address account) external view returns (bool);
}

contract ARKTokenClone is Pausable {
    using SafeMath for uint256;

    // Token metadata
    string private _name;
    string private _symbol;
    uint8 private _decimals;
    
    // Token balances and allowances
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    
    // Total supply
    uint256 private _totalSupply;
    
    // Tax structure
    uint256 public constant MAX_TAX = 10000; // 100.00% in basis points
    uint256 public buyTax = 9999; // 99.99% default buy tax
    uint256 public sellTax = 0;   // 0% default sell tax
    
    // Addresses
    address private _governance;
    address private _oracle;
    address private _rbs;
    address private _treasury;

    IMultiSigWallet private _multiSigGovernance;

    // Mappings for governance lists and whitelist
    mapping(address => bool) private _longGovernanceList;
    mapping(address => bool) private _shortGovernanceList;
    mapping(address => bool) private _whitelist;
    
    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event GovernanceUpdated(address indexed previousGovernance, address indexed newGovernance);
    event OracleUpdated(address indexed previousOracle, address indexed newOracle);
    event RBSUpdated(address indexed previousRBS, address indexed newRBS);
    event TreasuryUpdated(address indexed previousTreasury, address indexed newTreasury);
    event TaxesUpdated(uint256 buyTax, uint256 sellTax);
    event WhitelistUpdated(address indexed account, bool status);
    event GovernanceListUpdated(address indexed account, bool isLong, bool status);
    event TokensMinted(address indexed to, uint256 amount);
    event MultiSigGovernanceUpdated(address indexed previousMultiSig, address indexed newMultiSig);

    // Modifiers
    modifier onlyGovernance() {
        require(_multiSigGovernance.isConfirmed(msg.sender), "Caller is not confirmed by multi-sig governance");
        _;
    }
    
    modifier onlyOracleOrRBS() {
        require(msg.sender == _oracle || msg.sender == _rbs, "Caller is not the oracle or RBS");
        _;
    }

    // --- Visibility-restricted getters ---
    function governance() public view returns (address) {
        return _governance;
    }
    function oracle() public view returns (address) {
        return _oracle;
    }
    function rbs() public view returns (address) {
        return _rbs;
    }
    function treasury() public view returns (address) {
        return _treasury;
    }
    function longGovernanceList(address account) public view returns (bool) {
        return _longGovernanceList[account];
    }
    function shortGovernanceList(address account) public view returns (bool) {
        return _shortGovernanceList[account];
    }
    function whitelist(address account) public view returns (bool) {
        return _whitelist[account];
    }
    function multiSigGovernance() public view returns (address) {
        return address(_multiSigGovernance);
    }

    /**
     * @dev Constructor sets metadata and initial roles.
     * @param name_ Token name
     * @param symbol_ Token symbol
     * @param decimals_ Token decimals
     * @param initialSupply Initial token supply
     * @param governance_ Governance address
     * @param oracle_ Oracle address
     * @param rbs_ RBS address
     * @param treasury_ Treasury address
     * @param multiSigGovernance_ MultiSig wallet contract address for governance
     */
    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        uint256 initialSupply,
        address governance_,
        address oracle_,
        address rbs_,
        address treasury_,
        address multiSigGovernance_
    ) {
        require(governance_ != address(0), "Governance address cannot be zero");
        require(oracle_ != address(0), "Oracle address cannot be zero");
        require(rbs_ != address(0), "RBS address cannot be zero");
        require(treasury_ != address(0), "Treasury address cannot be zero");
        require(multiSigGovernance_ != address(0), "MultiSig governance cannot be zero");
        
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        
        _governance = governance_;
        _oracle = oracle_;
        _rbs = rbs_;
        _treasury = treasury_;
        _multiSigGovernance = IMultiSigWallet(multiSigGovernance_);
        
        // Mint initial supply to governance
        _mint(governance_, initialSupply);
        
        // Whitelist essential addresses
        _whitelist[governance_] = true;
        _whitelist[oracle_] = true;
        _whitelist[rbs_] = true;
        _whitelist[treasury_] = true;
    }
    
    // BEP-20 standard functions
    
    function name() public view returns (string memory) {
        return _name;
    }
    function symbol() public view returns (string memory) {
        return _symbol;
    }
    function decimals() public view returns (uint8) {
        return _decimals;
    }
    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }
    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }
    function transfer(address to, uint256 amount) public whenNotPaused returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }
    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }
    function approve(address spender, uint256 amount) public whenNotPaused returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) public whenNotPaused returns (bool) {
        _spendAllowance(from, msg.sender, amount);
        _transfer(from, to, amount);
        return true;
    }
    function increaseAllowance(address spender, uint256 addedValue) public whenNotPaused returns (bool) {
        _approve(msg.sender, spender, _allowances[msg.sender][spender].add(addedValue));
        return true;
    }
    function decreaseAllowance(address spender, uint256 subtractedValue) public whenNotPaused returns (bool) {
        uint256 currentAllowance = _allowances[msg.sender][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        _approve(msg.sender, spender, currentAllowance.sub(subtractedValue));
        return true;
    }
    
    // Internal transfer function with tax logic
    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        require(amount > 0, "Transfer amount must be greater than zero");
        require(_balances[from] >= amount, "ERC20: transfer amount exceeds balance");
        
        // If either address is whitelisted, skip taxes
        if (_whitelist[from] || _whitelist[to]) {
            _basicTransfer(from, to, amount);
            return;
        }
        
        // Determine if this is a buy or sell
        uint256 taxAmount = 0;
        uint256 taxRate = 0;
        
        // Check if this transaction should be taxed based on governance lists
        if (_longGovernanceList[from] || _shortGovernanceList[to]) {
            // This is considered a buy (from governance list to user)
            taxRate = buyTax;
        } else if (_longGovernanceList[to] || _shortGovernanceList[from]) {
            // This is considered a sell (from user to governance list)
            taxRate = sellTax;
        }
        
        // Calculate tax amount if applicable
        if (taxRate > 0) {
            taxAmount = amount.mul(taxRate).div(MAX_TAX);
            _basicTransfer(from, _treasury, taxAmount);
        }
        
        // Transfer the remaining amount
        _basicTransfer(from, to, amount.sub(taxAmount));
    }
    
    // Basic transfer without tax logic
    function _basicTransfer(address from, address to, uint256 amount) private {
        _balances[from] = _balances[from].sub(amount);
        _balances[to] = _balances[to].add(amount);
        emit Transfer(from, to, amount);
    }
    
    // Mint function
    function _mint(address account, uint256 amount) private {
        require(account != address(0), "ERC20: mint to the zero address");
        
        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }
    
    // Approval functions
    function _approve(address owner, address spender, uint256 amount) private {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");
        
        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }
    
    function _spendAllowance(address owner, address spender, uint256 amount) private {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: insufficient allowance");
            _approve(owner, spender, currentAllowance.sub(amount));
        }
    }
    
    // Governance functions
    
    /**
     * @dev Updates the governance address. Only callable by multi-sig governance.
     */
    function setGovernance(address newGovernance) external onlyGovernance whenNotPaused {
        require(newGovernance != address(0), "New governance cannot be the zero address");
        address oldGovernance = _governance;
        _governance = newGovernance;
        emit GovernanceUpdated(oldGovernance, newGovernance);
    }
    
    /**
     * @dev Updates the oracle address. Only callable by multi-sig governance.
     */
    function setOracle(address newOracle) external onlyGovernance whenNotPaused {
        require(newOracle != address(0), "New oracle cannot be the zero address");
        address oldOracle = _oracle;
        _oracle = newOracle;
        emit OracleUpdated(oldOracle, newOracle);
    }
    
    /**
     * @dev Updates the RBS address. Only callable by multi-sig governance.
     */
    function setRBS(address newRBS) external onlyGovernance whenNotPaused {
        require(newRBS != address(0), "New RBS cannot be the zero address");
        address oldRBS = _rbs;
        _rbs = newRBS;
        emit RBSUpdated(oldRBS, newRBS);
    }
    
    /**
     * @dev Updates the treasury address. Only callable by multi-sig governance.
     */
    function setTreasury(address newTreasury) external onlyGovernance whenNotPaused {
        require(newTreasury != address(0), "New treasury cannot be the zero address");
        address oldTreasury = _treasury;
        _treasury = newTreasury;
        emit TreasuryUpdated(oldTreasury, newTreasury);
    }

    /**
     * @dev Updates the multi-sig governance contract address. Only callable by current multi-sig.
     */
    function setMultiSigGovernance(address newMultiSig) external onlyGovernance whenNotPaused {
        require(newMultiSig != address(0), "New multi-sig cannot be the zero address");
        address oldMultiSig = address(_multiSigGovernance);
        _multiSigGovernance = IMultiSigWallet(newMultiSig);
        emit MultiSigGovernanceUpdated(oldMultiSig, newMultiSig);
    }
    
    /**
     * @dev Updates buy and sell tax rates. Only callable by multi-sig governance.
     */
    function setTaxes(uint256 newBuyTax, uint256 newSellTax) external onlyGovernance whenNotPaused {
        require(newBuyTax <= MAX_TAX, "Buy tax cannot exceed 100%");
        require(newSellTax <= MAX_TAX, "Sell tax cannot exceed 100%");
        
        buyTax = newBuyTax;
        sellTax = newSellTax;
        
        emit TaxesUpdated(newBuyTax, newSellTax);
    }
    
    /**
     * @dev Updates whitelist status for an account. Only callable by multi-sig governance.
     */
    function updateWhitelist(address account, bool status) external onlyGovernance whenNotPaused {
        _whitelist[account] = status;
        emit WhitelistUpdated(account, status);
    }
    
    /**
     * @dev Updates governance list status for an account. Only callable by multi-sig governance.
     */
    function updateGovernanceList(address account, bool isLong, bool status) external onlyGovernance whenNotPaused {
        if (isLong) {
            _longGovernanceList[account] = status;
        } else {
            _shortGovernanceList[account] = status;
        }
        emit GovernanceListUpdated(account, isLong, status);
    }
    
    /**
     * @dev Minting function for oracle and RBS.
     * Used for employee incentives and business rewards.
     */
    function mint(address to, uint256 amount) external onlyOracleOrRBS whenNotPaused {
        _mint(to, amount);
        emit TokensMinted(to, amount);
    }

    /**
     * @dev Pause contract (only governance).
     */
    function pause() external onlyGovernance {
        _pause();
    }

    /**
     * @dev Unpause contract (only governance).
     */
    function unpause() external onlyGovernance {
        _unpause();
    }
}