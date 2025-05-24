PROGRAM_FILE=./main.go
TEST_FILE=./service-now-plugin_test.go


GREP_RESULT=$(grep func ${PROGRAM_FILE}| awk '{print $4}'|awk -F'(' '{print $1}')

PREV_LINE_NUMBER=0
PREV_FUNCTION=""
ERROR_FOUND=0

echo "Order in ${PROGRAM_FILE}:"
echo ""

for FUNCTION in ${GREP_RESULT}
do
	echo ${FUNCTION}

	LINE_NUMBER=$(grep -n -i ${FUNCTION} ${TEST_FILE} | grep func | head -n 1 | awk -F':' '{print $1}')
	if test ${LINE_NUMBER} -lt ${PREV_LINE_NUMBER}
	then
		echo "${FUNCTION} is after ${PREV_FUNCTION} in main.go, it is before ${PREV_FUNCTION} in testset (${LINE_NUMBER}, ${PREV_LINE_NUMBER})"
		ERROR_FOUND=1
	fi

	PREV_LINE_NUMBER=${LINE_NUMBER}
	PREV_FUNCTION=${FUNCTION}
done

echo ""
if test ${ERROR_FOUND} -eq 0
then
	echo "Order in ${PROGRAM_FILE} is the same as in ${TEST_FILE}"
else
	echo "Errors found, please fix them"
	exit 1
fi
