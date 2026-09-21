// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title 취약한 은행 컨트랙트 (레드팀 시뮬레이터 테스트용 샘플)
/// @notice 재진입(Reentrancy), tx.origin 인증, unchecked 산술 취약점을 의도적으로 포함.
/// @dev 실제 서비스에 절대 배포하지 말 것. 로컬 Ganache 시뮬레이션 전용.
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /// @notice ETH 예치.
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice VULNERABILITY #1 (CRITICAL): 재진입 취약점.
    ///         외부 호출(msg.sender.call) 이후에 상태(balances)를 갱신하므로,
    ///         악의적인 수신 컨트랙트가 receive() 에서 withdraw를 재호출해
    ///         컨트랙트 잔액 전체를 반복 인출할 수 있다.
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        // CHECKS-EFFECTS-INTERACTIONS 위반: interaction 이 effect 보다 먼저 실행됨
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0; // 취약: 외부 호출 "이후" 상태 갱신
    }

    /// @notice VULNERABILITY #2 (HIGH): tx.origin 기반 인증.
    ///         피싱으로 소유자 EOA 가 악성 컨트랙트 트랜잭션에 서명하면
    ///         tx.origin == owner 가 통과되어 소유권이 탈취될 수 있다.
    function transferOwnershipTxOrigin(address newOwner) external {
        require(tx.origin == owner, "not owner");
        owner = newOwner;
    }

    /// @notice VULNERABILITY #3 (MEDIUM): unchecked 산술 — 오버플로우 가드 회피.
    function addCreditsUnchecked(uint256 amount) external returns (uint256) {
        uint256 credits = type(uint256).max - 1;
        unchecked {
            credits += amount; // 의도적 오버플로우 가능
        }
        balances[msg.sender] += credits;
        return credits;
    }

    /// @notice 컨트랙트 보유 ETH 조회.
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/// @title 안전한 은행 컨트랙트 (수정 제안의 기준 구현)
/// @notice Checks-Effects-Interactions 패턴 + 재진입 가드 적용.
contract SafeBank {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    constructor() {
        owner = msg.sender;
    }

    modifier noReentrant() {
        require(!locked, "reentrant call");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /// @notice 안전한 인출: 상태 갱신(Effect)을 외부 호출(Interaction)보다 먼저 수행.
    function withdraw() external noReentrant {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balances[msg.sender] = 0; // Effect 를 먼저
        (bool ok, ) = msg.sender.call{value: amount}(""); // Interaction 을 나중에
        require(ok, "transfer failed");
    }

    /// @notice 명시적 msg.sender 검증을 사용하는 소유권 이전 (안전).
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "not owner");
        require(newOwner != address(0), "zero address");
        owner = newOwner;
    }
}
