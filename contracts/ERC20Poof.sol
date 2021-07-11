pragma solidity 0.5.17;

import "./ERC20Tornado.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/SafeERC20.sol";

contract ERC20Poof is ERC20Tornado {
  using SafeERC20 for IERC20;

  address public governance;

  constructor(
    IVerifier _verifier,
    IFeeManager _feeManager,
    uint256 _denomination,
    uint32 _merkleTreeHeight,
    address _owner,
    address _token,
    address _governance
  ) ERC20Tornado(_verifier, _feeManager, _denomination, _merkleTreeHeight, _owner, _token) public {
    governance = _governance;
  }

  // @dev Claims tokens in contract to send back to governance
  // @param token The token address to claim
  function governanceClaim(IERC20 _token) external {
    uint256 balance = _token.balanceOf(address(this));
    require(balance > 0, "Can't claim a 0 amount");
    _token.safeTransfer(governance, balance);
  }
}
