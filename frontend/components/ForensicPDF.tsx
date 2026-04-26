'use client'
import { Document, Page, Text, View, StyleSheet } from '@react-pdf/renderer'
import { AnalyzeReport, verdictColor } from '@/lib/api'

const styles = StyleSheet.create({
  page:       { backgroundColor: '#0A0A0A', color: '#E8E8E8', padding: 40, fontFamily: 'Courier' },
  h1:         { fontSize: 20, fontWeight: 'bold', marginBottom: 8, color: '#E8E8E8' },
  h2:         { fontSize: 13, fontWeight: 'bold', marginBottom: 6, marginTop: 14, color: '#E8E8E8' },
  row:        { flexDirection: 'row', marginBottom: 4 },
  label:      { fontSize: 9, color: '#5A5A5A', width: 140 },
  value:      { fontSize: 9, color: '#E8E8E8', flex: 1 },
  scoreNum:   { fontSize: 48, fontWeight: 'bold', marginBottom: 4 },
  verdictLabel:{ fontSize: 20, fontWeight: 'bold', marginBottom: 12 },
  badge:      { fontSize: 9, paddingVertical: 3, paddingHorizontal: 6, marginRight: 6 },
  divider:    { borderBottomWidth: 1, borderBottomColor: '#333', marginVertical: 8 },
  flagRow:    { flexDirection: 'row', marginBottom: 4, fontSize: 8, gap: 8 },
  tag:        { fontSize: 7, paddingVertical: 2, paddingHorizontal: 4, fontWeight: 'bold' },
  gray:       { color: '#5A5A5A', fontSize: 8 },
})

interface Props {
  report: AnalyzeReport
}

export function ForensicPDFDoc({ report }: Props) {
  const { score, engines } = report
  const color = verdictColor(score.verdict)
  const headers = engines.headers
  const llm     = engines.llm

  return (
    <Document>
      <Page size="A4" style={styles.page}>
        {/* header */}
        <Text style={styles.h1}>PHISH-FILTER-PRO v1.0 — FORENSIC REPORT</Text>
        <View style={styles.row}>
          <Text style={styles.label}>JOB ID:</Text>
          <Text style={styles.value}>{report.job_id}</Text>
        </View>
        <View style={styles.row}>
          <Text style={styles.label}>ANALYZED:</Text>
          <Text style={styles.value}>{new Date(report.timestamp * 1000).toLocaleString()}</Text>
        </View>
        <View style={styles.row}>
          <Text style={styles.label}>INPUT TYPE:</Text>
          <Text style={styles.value}>{report.input_type.toUpperCase()}</Text>
        </View>

        <View style={styles.divider} />

        {/* verdict */}
        <Text style={[styles.scoreNum, { color }]}>{score.score}/100</Text>
        <Text style={[styles.verdictLabel, { color }]}>{score.verdict}</Text>
        <View style={styles.row}>
          <Text style={styles.label}>CONFIDENCE:</Text>
          <Text style={{ ...styles.value, color }}>{score.confidence}%</Text>
        </View>
        <View style={styles.row}>
          <Text style={styles.label}>ENGINES:</Text>
          <Text style={styles.value}>{score.engines_succeeded}/{score.engines_total} succeeded</Text>
        </View>

        <View style={styles.divider} />

        {/* auth */}
        {headers && (
          <>
            <Text style={styles.h2}>EMAIL AUTHENTICATION</Text>
            <View style={{ flexDirection: 'row', gap: 8, marginBottom: 8 }}>
              {(['spf', 'dkim', 'dmarc'] as const).map((k) => {
                const val = headers[k] ?? 'none'
                const c = val === 'pass' ? '#00FF41' : val === 'fail' || val === 'softfail' ? '#FF0044' : '#FFB800'
                return (
                  <View key={k} style={[styles.badge, { borderWidth: 1, borderColor: c }]}>
                    <Text style={{ color: c, fontSize: 9 }}>
                      {k.toUpperCase()}: {val.toUpperCase()}
                    </Text>
                  </View>
                )
              })}
            </View>
            {headers.mismatches?.length > 0 && (
              <View style={styles.row}>
                <Text style={styles.label}>MISMATCHES:</Text>
                <Text style={{ ...styles.value, color: '#FF0044' }}>
                  {headers.mismatches.join(', ')}
                </Text>
              </View>
            )}
          </>
        )}

        {/* score breakdown */}
        {score.breakdown.length > 0 && (
          <>
            <View style={styles.divider} />
            <Text style={styles.h2}>SCORE BREAKDOWN</Text>
            {score.breakdown.map((b, i) => (
              <View key={i} style={styles.row}>
                <Text style={{ ...styles.label, color }}>[+{b.contribution}]</Text>
                <Text style={styles.value}>{b.signal}: {b.reasoning.slice(0, 100)}</Text>
              </View>
            ))}
          </>
        )}

        {/* LLM */}
        {llm && !llm.error && (
          <>
            <View style={styles.divider} />
            <Text style={styles.h2}>LLM ENSEMBLE ANALYSIS ({llm.model_count} models)</Text>
            <View style={styles.row}>
              <Text style={styles.label}>VERDICT:</Text>
              <Text style={{ ...styles.value, color: verdictColor(llm.verdict) }}>{llm.verdict}</Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>RISK SCORE:</Text>
              <Text style={styles.value}>{llm.risk_score}/100</Text>
            </View>
            <View style={styles.row}>
              <Text style={styles.label}>CONFIDENCE:</Text>
              <Text style={styles.value}>{llm.confidence}%</Text>
            </View>
            {llm.summary && (
              <View style={styles.row}>
                <Text style={styles.label}>SUMMARY:</Text>
                <Text style={styles.value}>{llm.summary}</Text>
              </View>
            )}
          </>
        )}

        {/* red flags */}
        {llm?.red_flags && llm.red_flags.length > 0 && (
          <>
            <View style={styles.divider} />
            <Text style={styles.h2}>RED FLAGS</Text>
            {llm.red_flags.slice(0, 15).map((f, i) => (
              <View key={i} style={styles.flagRow}>
                <Text style={{ ...styles.tag, backgroundColor: verdictColor(f.severity === 'critical' || f.severity === 'high' ? 'DANGEROUS' : f.severity === 'medium' ? 'SUSPICIOUS' : 'SAFE'), color: '#0A0A0A' }}>
                  {f.severity.toUpperCase().slice(0, 4)}
                </Text>
                <Text style={{ color: '#E8E8E8', fontSize: 8, flex: 1 }}>
                  [{f.category.toUpperCase()}] &quot;{f.evidence.slice(0, 80)}&quot; — {f.explanation.slice(0, 100)}
                </Text>
              </View>
            ))}
          </>
        )}

        <View style={styles.divider} />
        <Text style={styles.gray}>
          Generated by PHISH-FILTER-PRO v1.0 on {new Date().toISOString()}
        </Text>
        <Text style={styles.gray}>
          Report job_id: {report.job_id}
        </Text>
      </Page>
    </Document>
  )
}
