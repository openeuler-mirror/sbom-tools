package repodata

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMvnRegexpStr(t *testing.T) {

	mvnStr := "mvn(jline:jline:1)"
	mvnRegexp := regexp.MustCompile(mvnRegexpStr)
	mvnCoordinate := mvnRegexp.FindStringSubmatch(mvnStr)
	groupId := mvnCoordinate[1]
	artifactId := mvnCoordinate[2]
	version := mvnCoordinate[4]
	assert.EqualValues(t, groupId, "jline", "mvnStr:%s, %s error", mvnStr, "groupId")
	assert.EqualValues(t, artifactId, "jline", "mvnStr:%s, %s error", mvnStr, "artifactId")
	assert.EqualValues(t, version, "1", "mvnStr:%s, %s error", mvnStr, "version")

	mvnStr = "mvn(jline:jline)"
	mvnRegexp = regexp.MustCompile(mvnRegexpStr)
	mvnCoordinate = mvnRegexp.FindStringSubmatch(mvnStr)
	groupId = mvnCoordinate[1]
	artifactId = mvnCoordinate[2]
	version = mvnCoordinate[4]
	assert.EqualValues(t, groupId, "jline", "mvnStr:%s, %s error", mvnStr, "groupId")
	assert.EqualValues(t, artifactId, "jline", "mvnStr:%s, %s error", mvnStr, "artifactId")
	assert.EqualValues(t, version, "", "mvnStr:%s, %s error", mvnStr, "version")

	mvnStr = "mvn(ant-contrib:ant-contrib:xml:)"
	mvnRegexp = regexp.MustCompile(mvnRegexpStr)
	mvnCoordinate = mvnRegexp.FindStringSubmatch(mvnStr)
	groupId = mvnCoordinate[1]
	artifactId = mvnCoordinate[2]
	version = mvnCoordinate[4]
	assert.EqualValues(t, groupId, "ant-contrib", "mvnStr:%s, %s error", mvnStr, "groupId")
	assert.EqualValues(t, artifactId, "ant-contrib", "mvnStr:%s, %s error", mvnStr, "artifactId")
	assert.EqualValues(t, version, "", "mvnStr:%s, %s error", mvnStr, "version")

	mvnStr = "mvn(org.apache.lucene:lucene-benchmark:3.6.2)"
	mvnRegexp = regexp.MustCompile(mvnRegexpStr)
	mvnCoordinate = mvnRegexp.FindStringSubmatch(mvnStr)
	groupId = mvnCoordinate[1]
	artifactId = mvnCoordinate[2]
	version = mvnCoordinate[4]
	assert.EqualValues(t, groupId, "org.apache.lucene", "mvnStr:%s, %s error", mvnStr, "groupId")
	assert.EqualValues(t, artifactId, "lucene-benchmark", "mvnStr:%s, %s error", mvnStr, "artifactId")
	assert.EqualValues(t, version, "3.6.2", "mvnStr:%s, %s error", mvnStr, "version")

	mvnStr = "mvn(org.apache.lucene:lucene-benchmark)"
	mvnRegexp = regexp.MustCompile(mvnRegexpStr)
	mvnCoordinate = mvnRegexp.FindStringSubmatch(mvnStr)
	groupId = mvnCoordinate[1]
	artifactId = mvnCoordinate[2]
	version = mvnCoordinate[4]
	assert.EqualValues(t, groupId, "org.apache.lucene", "mvnStr:%s, %s error", mvnStr, "groupId")
	assert.EqualValues(t, artifactId, "lucene-benchmark", "mvnStr:%s, %s error", mvnStr, "artifactId")
	assert.EqualValues(t, version, "", "mvnStr:%s, %s error", mvnStr, "version")

	mvnStr = "mvn(org.eclipse.emf.features:org.eclipse.emf.base::sources-feature:)"
	mvnRegexp = regexp.MustCompile(mvnRegexpStr)
	mvnCoordinate = mvnRegexp.FindStringSubmatch(mvnStr)
	groupId = mvnCoordinate[1]
	artifactId = mvnCoordinate[2]
	version = mvnCoordinate[4]
	assert.EqualValues(t, groupId, "org.eclipse.emf.features", "mvnStr:%s, %s error", mvnStr, "groupId")
	assert.EqualValues(t, artifactId, "org.eclipse.emf.base", "mvnStr:%s, %s error", mvnStr, "artifactId")
	assert.EqualValues(t, version, "", "mvnStr:%s, %s error", mvnStr, "version")

	mvnStr = "mvn(biz.aQute.bnd:bnd-baseline-maven-plugin::sources:)"
	mvnRegexp = regexp.MustCompile(mvnRegexpStr)
	mvnCoordinate = mvnRegexp.FindStringSubmatch(mvnStr)
	groupId = mvnCoordinate[1]
	artifactId = mvnCoordinate[2]
	version = mvnCoordinate[4]
	assert.EqualValues(t, groupId, "biz.aQute.bnd", "mvnStr:%s, %s error", mvnStr, "groupId")
	assert.EqualValues(t, artifactId, "bnd-baseline-maven-plugin", "mvnStr:%s, %s error", mvnStr, "artifactId")
	assert.EqualValues(t, version, "", "mvnStr:%s, %s error", mvnStr, "version")
}
