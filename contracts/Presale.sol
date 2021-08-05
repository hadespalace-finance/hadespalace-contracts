pragma solidity ^0.6.0;

library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, 'SafeMath: addition overflow');

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, 'SafeMath: subtraction overflow');
    }

    function sub(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, 'SafeMath: multiplication overflow');

        return c;
    }

    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, 'SafeMath: division by zero');
    }

    function div(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, 'SafeMath: modulo by zero');
    }

    function mod(
        uint256 a,
        uint256 b,
        string memory errorMessage
    ) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

interface IBEP20 {
    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address _owner, address spender) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 value
    ) external returns (bool ok);
}

contract HellFirePresale {
    using SafeMath for uint256;

    IBEP20 public TOKEN;
    
    address payable public owner;

    uint256 public sellStartAt = 1628334000;                  // August 7, 2021 11:00:00 AM UTC
    uint256 public sellEndAt = 1628938800;                    // August 14, 2021 11:00:00 AM UTC
    uint256 public claimStartAt = 1628938800;                 // August 14, 2021 11:00:00 AM UTC
    
    uint256 public totalTokensToSell = 2 * 10**20;            // 200 tokens for sell
    uint256 public tokenPerBnb = 10**18;                      // 1 BNB = 1 TOKEN
    uint256 public minPerTransaction = 0;                     // min amount per transaction
    uint256 public maxPerUser = 2 * 10**20;                   // max amount per user
    uint256 public totalSold;

    bool public saleEnded;
    
    mapping(address => uint256) public tokenPerAddresses;

    event tokensBought(address indexed user, uint256 amountSpent, uint256 amountBought, string tokenName, uint256 date);
    event tokensClaimed(address indexed user, uint256 amount, uint256 date);

    modifier checkSaleRequirements(uint256 buyAmount) {
        require(now >= sellStartAt && now < sellEndAt, 'Presale time mismatch');
        require(saleEnded == false, 'Sale disabled');
        require(
            buyAmount > 0 && buyAmount <= unsoldTokens(),
            'Insufficient buy amount'
        );
        _;
    }

    constructor(
        address _TOKEN        
    ) public {
        owner = msg.sender;
        TOKEN = IBEP20(_TOKEN);
    }

    // Function to buy TOKEN using BNB token
    function buyWithBNB(uint256 buyAmount) public payable checkSaleRequirements(buyAmount) {
        uint256 amount = calculateBNBAmount(buyAmount);
        require(msg.value >= amount, 'Insufficient BNB balance');
        require(buyAmount >= minPerTransaction, 'Lower than the minimal transaction amount');
        
        uint256 sumSoFar = tokenPerAddresses[msg.sender].add(buyAmount);
        require(sumSoFar <= maxPerUser, 'Greater than the maximum purchase limit');

        tokenPerAddresses[msg.sender] = sumSoFar;
        totalSold = totalSold.add(buyAmount);
                
        emit tokensBought(msg.sender, amount, buyAmount, 'BNB', now);
    }

    // Function to claim 
    function claimToken() public {
        require(now >= claimStartAt, "Claim time mismatch");
        uint256 boughtAmount = tokenPerAddresses[msg.sender];
        require(boughtAmount > 0, "Insufficient token amount");
        TOKEN.transfer(msg.sender, boughtAmount);
        tokenPerAddresses[msg.sender] = 0;

        emit tokensClaimed(msg.sender, boughtAmount, now);
    }

    //function to change the owner
    //only owner can call this function
    function changeOwner(address payable _owner) public {
        require(msg.sender == owner);
        owner = _owner;
    }

    // function to set the presale start date
    // only owner can call this function
    function setSellStartDate(uint256 _sellStartAt) public {
        require(msg.sender == owner && saleEnded == false);
        sellStartAt = _sellStartAt;
    }

    // function to set the presale end date
    // only owner can call this function
    function setSellEndDate(uint256 _sellEndAt) public {
        require(msg.sender == owner && saleEnded == false);
        sellEndAt = _sellEndAt;
    }

    // function to set the token claim start date
    // only owner can call this function
    function setClaimStartDate(uint256 _claimStartAt) public {
        require(msg.sender == owner);
        claimStartAt = _claimStartAt;
    }

    // function to set the total tokens to sell
    // only owner can call this function
    function setTotalTokensToSell(uint256 _totalTokensToSell) public {
        require(msg.sender == owner);
        totalTokensToSell = _totalTokensToSell;
    }

    // function to set the minimal transaction amount
    // only owner can call this function
    function setMinPerTransaction(uint256 _minPerTransaction) public {
        require(msg.sender == owner);
        minPerTransaction = _minPerTransaction;
    }

    // function to set the maximum amount which a user can buy
    // only owner can call this function
    function setMaxPerUser(uint256 _maxPerUser) public {
        require(msg.sender == owner);
        maxPerUser = _maxPerUser;
    }

    // function to set the total tokens to sell
    // only owner can call this function
    function setTokenPricePerBNB(uint256 _tokenPerBnb) public {
        require(msg.sender == owner);
        require(_tokenPerBnb > 0, "Invalid TOKEN price per BNB");
        tokenPerBnb = _tokenPerBnb;
    }

    //function to end the sale
    //only owner can call this function
    function endSale() public {
        require(msg.sender == owner && saleEnded == false);
        saleEnded = true;
    }

    //function to withdraw collected tokens by sale.
    //only owner can call this function

    function withdrawCollectedTokens() public {
        require(msg.sender == owner);
        require(address(this).balance > 0, "Insufficient balance");
        owner.transfer(address(this).balance);
    }

    //function to withdraw unsold tokens
    //only owner can call this function
    function withdrawUnsoldTokens() public {
        require(msg.sender == owner);
        uint256 remainedTokens = unsoldTokens();
        require(remainedTokens > 0, "No remained tokens");
        TOKEN.transfer(owner, remainedTokens);
    }

    //function to return the amount of unsold tokens
    function unsoldTokens() public view returns (uint256) {
        // return totalTokensToSell.sub(totalSold);
        return TOKEN.balanceOf(address(this));
    }

    //function to calculate the quantity of TOKEN based on the TOKEN price of bnbAmount
    function calculateTokenAmount(uint256 bnbAmount) public view returns (uint256) {
        uint256 tokenAmount = tokenPerBnb.mul(bnbAmount).div(10**18);
        return tokenAmount;
    }

    //function to calculate the quantity of bnb needed using its TOKEN price to buy `buyAmount` of TOKEN
    function calculateBNBAmount(uint256 tokenAmount) public view returns (uint256) {
        require(tokenPerBnb > 0, "TOKEN price per BNB should be greater than 0");
        uint256 bnbAmount = tokenAmount.mul(10**18).div(tokenPerBnb);
        return bnbAmount;
    }
}
