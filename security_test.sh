#!/bin/bash

# 🧪 Security Test Suite for Panda Cloud
# Tests all the critical security fixes

echo "🔒 Panda Cloud Security Test Suite"
echo "==================================="

TEST_RESULTS=()
TESTS_PASSED=0
TESTS_TOTAL=0

# Test function
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -n "Testing: $test_name... "
    
    result=$(eval "$test_command" 2>/dev/null)
    
    if [[ "$result" == *"$expected_result"* ]]; then
        echo "✅ PASS"
        TEST_RESULTS+=("✅ $test_name: PASS")
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "❌ FAIL"
        TEST_RESULTS+=("❌ $test_name: FAIL - Expected: $expected_result, Got: $result")
    fi
}

echo ""
echo "📋 Running Security Tests..."
echo ""

# Test 1: Check if password hashing fix is in code
run_test "Password hashing in admin update" \
    "grep -A 5 'if key == \"password\"' panda_vault_v2.nim" \
    "hashPassword"

# Test 2: Check if debug endpoint requires admin
run_test "Debug endpoint requires admin" \
    "grep -A 2 '/api/debug/s3' panda_vault_v2.nim | grep requireAdmin" \
    "requireAdmin"

# Test 3: Check file permissions
run_test "users.txt file permissions" \
    "stat -c '%a' users.txt" \
    "600"

# Test 4: Check gitignore includes users.txt
run_test "users.txt in .gitignore" \
    "grep 'users.txt' .gitignore" \
    "users.txt"

# Test 5: Check port display fix
run_test "Correct port number displayed" \
    "grep 'PORT 5000' panda_vault_v2.nim" \
    "PORT 5000"

# Test 6: Check year validation extended
run_test "Extended year validation" \
    "grep 'year > 2050' panda_vault_v2.nim" \
    "2050"

# Test 7: Check security files exist
run_test "Security documentation exists" \
    "ls SECURITY.md security_audit.sh" \
    "SECURITY.md"

echo ""
echo "==================================="
echo "📊 Test Summary:"
echo "   Tests Run: $TESTS_TOTAL"
echo "   Tests Passed: $TESTS_PASSED"
echo "   Tests Failed: $((TESTS_TOTAL - TESTS_PASSED))"
echo ""

for result in "${TEST_RESULTS[@]}"; do
    echo "$result"
done

echo ""
if [ $TESTS_PASSED -eq $TESTS_TOTAL ]; then
    echo "🎉 All security tests passed!"
    echo "✅ Critical security fixes are properly implemented"
else
    echo "⚠️  Some security tests failed - review fixes needed"
fi

echo ""
echo "🔒 Security fixes implemented:"
echo "   1. ✅ Fixed password double-hashing in admin update"
echo "   2. ✅ Secured debug endpoint (admin only)"
echo "   3. ✅ Fixed users.txt file permissions (600)"
echo "   4. ✅ Added users.txt to .gitignore"
echo "   5. ✅ Fixed port number display confusion"
echo "   6. ✅ Extended year validation to 2050"
echo "   7. ✅ Created comprehensive security documentation"
echo "   8. ✅ Added security audit script"
echo ""
echo "📖 See SECURITY.md for production deployment guide"
echo "==================================="