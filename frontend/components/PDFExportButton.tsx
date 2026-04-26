'use client'
import { BlobProvider } from '@react-pdf/renderer'
import { ForensicPDFDoc } from './ForensicPDF'
import { AnalyzeReport } from '@/lib/api'

interface Props {
  report: AnalyzeReport
  jobId: string
}

export default function PDFExportButton({ report, jobId }: Props) {
  return (
    <BlobProvider document={<ForensicPDFDoc report={report} />}>
      {({ url, loading, error }) => (
        <a
          href={url ?? '#'}
          download={`phishfilter-${jobId.slice(0, 8)}.pdf`}
          style={{ textDecoration: 'none' }}
          onClick={(e) => { if (!url) e.preventDefault() }}
        >
          <button
            className="rounded-lg border border-[#e5e7eb] bg-white px-3 py-2 text-[13px] font-medium text-[#111827] hover:bg-[#f8fafc] disabled:cursor-not-allowed disabled:opacity-60"
            disabled={loading || !!error}
          >
            {loading ? 'Generating PDF...'
              : error ? 'PDF unavailable'
              : 'Export PDF'}
          </button>
        </a>
      )}
    </BlobProvider>
  )
}
