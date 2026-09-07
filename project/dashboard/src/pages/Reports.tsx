/**
 * Enterprise Reports Page
 *
 * Full-featured reporting system with:
 * - Multiple report types with templates
 * - PDF preview and generation
 * - Scheduled reports
 * - Executive summaries
 * - Custom report builder
 */

import { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  DocumentTextIcon,
  PlusIcon,
  ArrowDownTrayIcon,
  TrashIcon,
  XMarkIcon,
  ClockIcon,
  CheckCircleIcon,
  ExclamationCircleIcon,
  CalendarDaysIcon,
  ChartBarIcon,
  ShieldCheckIcon,
  DocumentChartBarIcon,
  PresentationChartBarIcon,
  AdjustmentsHorizontalIcon,
  EyeIcon,
  PaperAirplaneIcon,
  ArrowPathIcon,
  FunnelIcon,
  MagnifyingGlassIcon,
  BellIcon,
  Cog6ToothIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { format, subDays, subMonths, startOfMonth, endOfMonth, startOfWeek, endOfWeek } from 'date-fns';
import api from '../services/api';
import { Report, ReportType, ReportFormat } from '../types';
import { PageHeader } from '../components/ui';

// ============================================================================
// Types
// ============================================================================

interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  type: ReportType;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  color: string;
  sections: string[];
  estimatedPages: number;
}

interface ScheduledReport {
  id: string;
  template: string;
  schedule: 'daily' | 'weekly' | 'monthly';
  recipients: string[];
  nextRun: Date;
  enabled: boolean;
}

interface ReportFormData {
  report_type: ReportType;
  format: ReportFormat;
  start_date: string;
  end_date: string;
  include_charts: boolean;
  include_details: boolean;
  sections: string[];
  recipients: string[];
}

// ============================================================================
// Constants
// ============================================================================

const REPORT_TEMPLATES: ReportTemplate[] = [
  {
    id: 'executive',
    name: 'Executive Summary',
    description: 'High-level overview for leadership with key metrics and trends',
    type: ReportType.EXECUTIVE,
    icon: PresentationChartBarIcon,
    color: 'from-purple-500 to-indigo-600',
    sections: ['Key Metrics', 'Attack Summary', 'Traffic Trends', 'Recommendations'],
    estimatedPages: 4,
  },
  {
    id: 'incident',
    name: 'Incident Report',
    description: 'Detailed analysis of specific attack incidents with timeline',
    type: ReportType.INCIDENT,
    icon: ShieldCheckIcon,
    color: 'from-red-500 to-orange-600',
    sections: ['Attack Timeline', 'Impact Analysis', 'Mitigation Actions', 'Root Cause', 'Lessons Learned'],
    estimatedPages: 8,
  },
  {
    id: 'traffic',
    name: 'Traffic Analysis',
    description: 'Comprehensive traffic patterns, protocols, and bandwidth usage',
    type: ReportType.TRAFFIC,
    icon: ChartBarIcon,
    color: 'from-cyan-500 to-blue-600',
    sections: ['Bandwidth Summary', 'Protocol Breakdown', 'Top Sources', 'Geographic Distribution', 'Trends'],
    estimatedPages: 12,
  },
  {
    id: 'security',
    name: 'Security Audit',
    description: 'Security posture assessment with vulnerabilities and recommendations',
    type: ReportType.SECURITY,
    icon: DocumentChartBarIcon,
    color: 'from-emerald-500 to-teal-600',
    sections: ['Threat Landscape', 'Blocked Attacks', 'IP Reputation', 'Policy Effectiveness', 'Compliance'],
    estimatedPages: 15,
  },
  {
    id: 'sla',
    name: 'SLA Compliance',
    description: 'Service level agreement metrics and uptime reporting',
    type: ReportType.SLA,
    icon: DocumentTextIcon,
    color: 'from-amber-500 to-yellow-600',
    sections: ['Uptime Metrics', 'Response Times', 'Mitigation SLAs', 'Breach Analysis', 'Trend Charts'],
    estimatedPages: 6,
  },
  {
    id: 'custom',
    name: 'Custom Report',
    description: 'Build your own report with selected sections and metrics',
    type: ReportType.CUSTOM,
    icon: AdjustmentsHorizontalIcon,
    color: 'from-slate-500 to-slate-700',
    sections: [],
    estimatedPages: 0,
  },
];

const DATE_PRESETS = [
  { label: 'Last 24 Hours', getValue: () => ({ start: subDays(new Date(), 1), end: new Date() }) },
  { label: 'Last 7 Days', getValue: () => ({ start: subDays(new Date(), 7), end: new Date() }) },
  { label: 'Last 30 Days', getValue: () => ({ start: subDays(new Date(), 30), end: new Date() }) },
  { label: 'This Week', getValue: () => ({ start: startOfWeek(new Date()), end: endOfWeek(new Date()) }) },
  { label: 'This Month', getValue: () => ({ start: startOfMonth(new Date()), end: endOfMonth(new Date()) }) },
  { label: 'Last Month', getValue: () => ({ start: startOfMonth(subMonths(new Date(), 1)), end: endOfMonth(subMonths(new Date(), 1)) }) },
];

const STATUS_CONFIG: Record<string, { color: string; icon: React.ComponentType<React.SVGProps<SVGSVGElement>> }> = {
  pending: { color: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400', icon: ClockIcon },
  generating: { color: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400', icon: ArrowPathIcon },
  completed: { color: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400', icon: CheckCircleIcon },
  failed: { color: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400', icon: ExclamationCircleIcon },
};


// ============================================================================
// Sub-components
// ============================================================================

function TemplateCard({
  template,
  selected,
  onClick,
}: {
  template: ReportTemplate;
  selected: boolean;
  onClick: () => void;
}) {
  const Icon = template.icon;

  return (
    <button
      onClick={onClick}
      className={clsx(
        'relative p-4 rounded-xl border-2 text-left transition-all duration-200',
        selected
          ? 'border-brand-500 bg-brand-50 dark:bg-brand-500/10 ring-2 ring-brand-500/20'
          : 'border-slate-200 dark:border-slate-700 hover:border-slate-300 dark:hover:border-slate-300 dark:border-slate-600 hover:bg-slate-50 dark:hover:bg-slate-800/50'
      )}
    >
      <div className={clsx('inline-flex p-2.5 rounded-lg bg-gradient-to-br', template.color)}>
        <Icon className="h-5 w-5 text-slate-900 dark:text-white" />
      </div>
      <h4 className="mt-3 font-semibold text-slate-900 dark:text-white">{template.name}</h4>
      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400 line-clamp-2">
        {template.description}
      </p>
      <div className="mt-3 flex items-center gap-2 text-xs text-slate-400 dark:text-slate-500">
        <DocumentTextIcon className="h-3.5 w-3.5" />
        <span>{template.estimatedPages > 0 ? `~${template.estimatedPages} pages` : 'Variable'}</span>
      </div>
      {selected && (
        <div className="absolute top-3 right-3">
          <CheckCircleIcon className="h-5 w-5 text-brand-500" />
        </div>
      )}
    </button>
  );
}

function ReportPreview({ template, dateRange }: { template: ReportTemplate; dateRange: { start: string; end: string } }) {
  return (
    <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden">
      {/* Preview Header */}
      <div className={clsx('px-6 py-4 bg-gradient-to-r', template.color)}>
        <div className="flex items-center gap-3">
          <template.icon className="h-8 w-8 text-slate-900 dark:text-white" />
          <div>
            <h3 className="text-lg font-bold text-slate-900 dark:text-white">{template.name}</h3>
            <p className="text-sm text-slate-900 dark:text-white/80">
              {dateRange.start} to {dateRange.end}
            </p>
          </div>
        </div>
      </div>

      {/* Preview Content */}
      <div className="p-6 space-y-6">
        {/* Sections Included */}
        <div>
          <h4 className="text-sm font-semibold text-slate-900 dark:text-white mb-3">Sections Included</h4>
          <ul className="space-y-1.5">
            {template.sections.map((section) => (
              <li key={section} className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
                <CheckCircleIcon className="h-4 w-4 text-emerald-500" />
                {section}
              </li>
            ))}
          </ul>
        </div>

        {/* Data source info */}
        <div className="p-4 bg-indigo-50 dark:bg-indigo-500/10 rounded-lg border border-indigo-200 dark:border-indigo-500/20">
          <p className="text-sm font-medium text-indigo-800 dark:text-indigo-300">
            Real Data Report
          </p>
          <p className="text-xs text-indigo-600 dark:text-indigo-400 mt-1">
            Report will be generated using actual traffic rollups and attack history from the database for the selected date range.
          </p>
        </div>
      </div>

      {/* Preview Footer */}
      <div className="px-6 py-3 bg-slate-50 dark:bg-slate-700/50 border-t border-slate-200 dark:border-slate-700">
        <p className="text-xs text-slate-500 dark:text-slate-400 text-center">
          ~{template.estimatedPages > 0 ? template.estimatedPages : '?'} pages estimated
        </p>
      </div>
    </div>
  );
}

function ScheduledReportCard({ report, templates }: { report: ScheduledReport; templates: ReportTemplate[] }) {
  const template = templates.find((t) => t.id === report.template);
  if (!template) return null;

  return (
    <div className={clsx(
      'p-4 rounded-lg border transition-opacity',
      report.enabled
        ? 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800'
        : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 opacity-60'
    )}>
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className={clsx('p-2 rounded-lg bg-gradient-to-br', template.color)}>
            <template.icon className="h-4 w-4 text-slate-900 dark:text-white" />
          </div>
          <div>
            <h4 className="font-medium text-slate-900 dark:text-white">{template.name}</h4>
            <p className="text-sm text-slate-500 dark:text-slate-400 capitalize">{report.schedule}</p>
          </div>
        </div>
        <button className="p-1 hover:bg-slate-100 dark:hover:bg-slate-700 rounded">
          <Cog6ToothIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
        </button>
      </div>
      <div className="mt-3 flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400">
        <div className="flex items-center gap-1">
          <CalendarDaysIcon className="h-3.5 w-3.5" />
          <span>Next: {format(report.nextRun, 'MMM d, yyyy')}</span>
        </div>
        <div className="flex items-center gap-1">
          <BellIcon className="h-3.5 w-3.5" />
          <span>{report.recipients.length} recipients</span>
        </div>
      </div>
    </div>
  );
}

function ScheduledReportsTab({ templates }: { templates: ReportTemplate[] }) {
  const { data: scheduledReports, isLoading } = useQuery({
    queryKey: ['scheduled-reports'],
    queryFn: () => api.getScheduledReports() as unknown as Promise<ScheduledReport[]>,
    refetchInterval: 30000,
  });

  const reports = scheduledReports || [];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div className="lg:col-span-2 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Active Schedules</h3>
        </div>

        {isLoading ? (
          <div className="p-8 text-center text-slate-500 dark:text-slate-400">Loading scheduled reports...</div>
        ) : reports.length > 0 ? (
          <div className="space-y-3">
            {reports.map((report) => (
              <ScheduledReportCard key={report.id} report={report} templates={templates} />
            ))}
          </div>
        ) : (
          <div className="p-8 text-center">
            <CalendarDaysIcon className="h-12 w-12 mx-auto text-slate-500 dark:text-slate-400" />
            <p className="mt-3 text-sm font-medium text-slate-900 dark:text-white">No scheduled reports</p>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              Scheduled reports can be configured via the API.
            </p>
          </div>
        )}
      </div>

      <div className="space-y-4">
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Upcoming Reports</h3>
          </div>
          <div className="card-body">
            {reports.filter(r => r.enabled).length > 0 ? (
              <div className="space-y-3">
                {reports
                  .filter(r => r.enabled)
                  .sort((a, b) => new Date(a.nextRun).getTime() - new Date(b.nextRun).getTime())
                  .slice(0, 5)
                  .map(report => {
                    const template = templates.find(t => t.id === report.template);
                    return (
                      <div key={report.id} className="flex items-center justify-between py-2 border-b border-slate-100 dark:border-slate-700 last:border-0">
                        <div className="flex items-center gap-2">
                          {template && <template.icon className="h-4 w-4 text-slate-500 dark:text-slate-400" />}
                          <span className="text-sm text-slate-900 dark:text-white">{template?.name || report.template}</span>
                        </div>
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          {format(new Date(report.nextRun), 'MMM d')}
                        </span>
                      </div>
                    );
                  })}
              </div>
            ) : (
              <p className="text-sm text-slate-500 dark:text-slate-400">No upcoming reports</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function ReportsPage() {
  const queryClient = useQueryClient();

  // State
  const [activeTab, setActiveTab] = useState<'generate' | 'history' | 'scheduled'>('generate');
  const [selectedTemplate, setSelectedTemplate] = useState<ReportTemplate>(REPORT_TEMPLATES[0]);
  const [showPreview, setShowPreview] = useState(false);
  const [page, setPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  const [formData, setFormData] = useState<ReportFormData>({
    report_type: ReportType.EXECUTIVE,
    format: ReportFormat.PDF,
    start_date: format(subDays(new Date(), 7), 'yyyy-MM-dd'),
    end_date: format(new Date(), 'yyyy-MM-dd'),
    include_charts: true,
    include_details: true,
    sections: REPORT_TEMPLATES[0].sections,
    recipients: [],
  });

  // Fetch reports history
  const { data: reportsData, isLoading } = useQuery({
    queryKey: ['reports', page, typeFilter],
    queryFn: () => api.getReports({
      page,
      per_page: 10,
      ...(typeFilter !== 'all' ? { report_type: typeFilter } : {}),
    }),
    refetchInterval: 10000,
  });

  // Filtered reports
  const filteredReports = useMemo(() => {
    if (!reportsData?.items) return [];
    if (!searchQuery) return reportsData.items;
    return reportsData.items.filter((report: Report) =>
      report.report_type.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [reportsData, searchQuery]);

  // Generate report mutation
  const generateMutation = useMutation({
    mutationFn: () => api.generateReport({
      report_type: formData.report_type,
      format: formData.format,
      start_date: formData.start_date,
      end_date: formData.end_date,
      include_charts: formData.include_charts,
      include_details: formData.include_details,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      toast.success('Report generation started');
      setActiveTab('history');
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to generate report');
    },
  });

  // Delete report mutation
  const deleteMutation = useMutation({
    mutationFn: (reportId: string) => api.deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      toast.success('Report deleted');
    },
  });

  const handleDownload = async (report: Report) => {
    try {
      const blob = await api.downloadReport(report.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.report_type}_${format(new Date(report.start_date), 'yyyy-MM-dd')}_${report.id}.${report.format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success('Download started');
    } catch {
      toast.error('Failed to download report');
    }
  };

  const handleTemplateSelect = (template: ReportTemplate) => {
    setSelectedTemplate(template);
    setFormData((prev) => ({
      ...prev,
      report_type: template.type,
      sections: template.sections,
    }));
  };

  const handleDatePreset = (preset: typeof DATE_PRESETS[0]) => {
    const { start, end } = preset.getValue();
    setFormData((prev) => ({
      ...prev,
      start_date: format(start, 'yyyy-MM-dd'),
      end_date: format(end, 'yyyy-MM-dd'),
    }));
  };

  const formatFileSize = (bytes?: number): string => {
    if (!bytes) return '-';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        description="Generate, schedule, and manage security reports"
      />

      {/* Tabs */}
      <div className="border-b border-slate-200 dark:border-slate-700">
        <nav className="-mb-px flex gap-6">
          {[
            { id: 'generate', label: 'Generate Report', icon: PlusIcon },
            { id: 'history', label: 'Report History', icon: DocumentTextIcon },
            { id: 'scheduled', label: 'Scheduled Reports', icon: CalendarDaysIcon },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={clsx(
                'flex items-center gap-2 py-3 px-1 border-b-2 text-sm font-medium transition-colors',
                activeTab === tab.id
                  ? 'border-brand-500 text-brand-600 dark:text-brand-400'
                  : 'border-transparent text-slate-500 hover:text-slate-700 dark:hover:text-slate-200 dark:text-slate-300'
              )}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Generate Report Tab */}
      {activeTab === 'generate' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Template Selection & Options */}
          <div className="lg:col-span-2 space-y-6">
            {/* Template Selection */}
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Select Report Template</h3>
              </div>
              <div className="card-body">
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  {REPORT_TEMPLATES.map((template) => (
                    <TemplateCard
                      key={template.id}
                      template={template}
                      selected={selectedTemplate.id === template.id}
                      onClick={() => handleTemplateSelect(template)}
                    />
                  ))}
                </div>
              </div>
            </div>

            {/* Date Range */}
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Date Range</h3>
              </div>
              <div className="card-body space-y-4">
                {/* Quick Presets */}
                <div className="flex flex-wrap gap-2">
                  {DATE_PRESETS.map((preset) => (
                    <button
                      key={preset.label}
                      onClick={() => handleDatePreset(preset)}
                      className="px-3 py-1.5 text-sm bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors"
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>

                {/* Custom Date Inputs */}
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                      Start Date
                    </label>
                    <input
                      type="date"
                      value={formData.start_date}
                      onChange={(e) => setFormData((f) => ({ ...f, start_date: e.target.value }))}
                      className="w-full px-3 py-2 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
                      End Date
                    </label>
                    <input
                      type="date"
                      value={formData.end_date}
                      onChange={(e) => setFormData((f) => ({ ...f, end_date: e.target.value }))}
                      className="w-full px-3 py-2 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Report Options */}
            <div className="card">
              <div className="card-header">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Report Options</h3>
              </div>
              <div className="card-body space-y-4">
                {/* Format Selection */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                    Output Format
                  </label>
                  <div className="flex gap-3">
                    {[
                      { value: ReportFormat.PDF, label: 'PDF', desc: 'Best for sharing' },
                      { value: ReportFormat.HTML, label: 'HTML', desc: 'Interactive' },
                      { value: ReportFormat.CSV, label: 'CSV', desc: 'Raw data' },
                      { value: ReportFormat.JSON, label: 'JSON', desc: 'API/Integration' },
                    ].map((fmt) => (
                      <button
                        key={fmt.value}
                        onClick={() => setFormData((f) => ({ ...f, format: fmt.value }))}
                        className={clsx(
                          'flex-1 p-3 rounded-lg border-2 text-center transition-all',
                          formData.format === fmt.value
                            ? 'border-brand-500 bg-brand-50 dark:bg-brand-500/10'
                            : 'border-slate-200 dark:border-slate-700 hover:border-slate-300'
                        )}
                      >
                        <p className="font-semibold text-slate-900 dark:text-white">{fmt.label}</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">{fmt.desc}</p>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Include Options */}
                <div className="grid grid-cols-2 gap-4">
                  <label className="flex items-center gap-3 p-3 bg-slate-50 dark:bg-slate-800 rounded-lg cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.include_charts}
                      onChange={(e) => setFormData((f) => ({ ...f, include_charts: e.target.checked }))}
                      className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                    />
                    <div>
                      <p className="font-medium text-slate-900 dark:text-white">Include Charts</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Visual graphs and charts</p>
                    </div>
                  </label>
                  <label className="flex items-center gap-3 p-3 bg-slate-50 dark:bg-slate-800 rounded-lg cursor-pointer">
                    <input
                      type="checkbox"
                      checked={formData.include_details}
                      onChange={(e) => setFormData((f) => ({ ...f, include_details: e.target.checked }))}
                      className="h-4 w-4 rounded border-slate-300 text-brand-600 focus:ring-brand-500"
                    />
                    <div>
                      <p className="font-medium text-slate-900 dark:text-white">Detailed Data</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">Raw data tables</p>
                    </div>
                  </label>
                </div>
              </div>
            </div>

            {/* Generate Actions */}
            <div className="flex items-center justify-between p-4 bg-slate-50 dark:bg-slate-800 rounded-xl">
              <button
                onClick={() => setShowPreview(true)}
                className="btn btn-secondary flex items-center gap-2"
              >
                <EyeIcon className="h-4 w-4" />
                Preview Report
              </button>
              <button
                onClick={() => generateMutation.mutate()}
                disabled={generateMutation.isPending}
                className="btn btn-primary flex items-center gap-2"
              >
                {generateMutation.isPending ? (
                  <>
                    <ArrowPathIcon className="h-4 w-4 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <PaperAirplaneIcon className="h-4 w-4" />
                    Generate Report
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Right: Preview */}
          <div className="lg:col-span-1">
            <div className="sticky top-24">
              <ReportPreview
                template={selectedTemplate}
                dateRange={{ start: formData.start_date, end: formData.end_date }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Report History Tab */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-4">
            <div className="relative flex-1 max-w-md">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-500 dark:text-slate-400" />
              <input
                type="text"
                placeholder="Search reports..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white"
              />
            </div>
            <div className="flex items-center gap-2">
              <FunnelIcon className="h-5 w-5 text-slate-500 dark:text-slate-400" />
              <select
                value={typeFilter}
                onChange={(e) => setTypeFilter(e.target.value)}
                className="px-3 py-2 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg text-slate-900 dark:text-white"
              >
                <option value="all">All Types</option>
                {Object.values(ReportType).map((type) => (
                  <option key={type} value={type}>{type.charAt(0).toUpperCase() + type.slice(1)}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Reports Table */}
          <div className="card overflow-hidden">
            {isLoading ? (
              <div className="p-8 text-center">
                <ArrowPathIcon className="h-8 w-8 mx-auto text-slate-500 dark:text-slate-400 animate-spin" />
                <p className="mt-2 text-sm text-slate-500">Loading reports...</p>
              </div>
            ) : filteredReports.length > 0 ? (
              <>
                <table className="w-full">
                  <thead className="bg-slate-50 dark:bg-slate-800/50">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Report
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Date Range
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Format
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Size
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Generated
                      </th>
                      <th className="px-4 py-3 text-right text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {filteredReports.map((report: Report) => {
                      const template = REPORT_TEMPLATES.find((t) => t.type === report.report_type);
                      const statusConfig = STATUS_CONFIG[report.status] || STATUS_CONFIG.pending;
                      const StatusIcon = statusConfig.icon;

                      return (
                        <tr key={report.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-3">
                              {template && (
                                <div className={clsx('p-2 rounded-lg bg-gradient-to-br', template.color)}>
                                  <template.icon className="h-4 w-4 text-slate-900 dark:text-white" />
                                </div>
                              )}
                              <div>
                                <p className="font-medium text-slate-900 dark:text-white">
                                  {template?.name || report.report_type}
                                </p>
                                <p className="text-xs text-slate-500 dark:text-slate-400">
                                  ID: {report.id.slice(0, 8)}
                                </p>
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                            {format(new Date(report.start_date), 'MMM d')} - {format(new Date(report.end_date), 'MMM d, yyyy')}
                          </td>
                          <td className="px-4 py-3">
                            <span className="inline-flex px-2 py-1 text-xs font-medium bg-slate-100 dark:bg-slate-700 text-slate-700 dark:text-slate-300 rounded uppercase">
                              {report.format}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span className={clsx(
                              'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium',
                              statusConfig.color
                            )}>
                              <StatusIcon className={clsx('h-3.5 w-3.5', report.status === 'generating' && 'animate-spin')} />
                              {report.status}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                            {formatFileSize(report.file_size_bytes)}
                          </td>
                          <td className="px-4 py-3 text-sm text-slate-600 dark:text-slate-300">
                            {format(new Date(report.generated_at), 'MMM d, yyyy HH:mm')}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center justify-end gap-2">
                              {report.status === 'completed' && (
                                <button
                                  onClick={() => handleDownload(report)}
                                  className="p-1.5 text-brand-600 hover:bg-brand-50 dark:hover:bg-brand-500/10 rounded-lg transition-colors"
                                  title="Download"
                                >
                                  <ArrowDownTrayIcon className="h-5 w-5" />
                                </button>
                              )}
                              <button
                                onClick={() => {
                                  if (confirm('Delete this report?')) {
                                    deleteMutation.mutate(report.id);
                                  }
                                }}
                                disabled={deleteMutation.isPending}
                                className="p-1.5 text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 rounded-lg transition-colors"
                                title="Delete"
                              >
                                <TrashIcon className="h-5 w-5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>

                {/* Pagination */}
                {reportsData && reportsData.pages > 1 && (
                  <div className="px-4 py-3 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between">
                    <span className="text-sm text-slate-500 dark:text-slate-400">
                      Page {reportsData.page} of {reportsData.pages} ({reportsData.total} reports)
                    </span>
                    <div className="flex gap-2">
                      <button
                        onClick={() => setPage((p) => Math.max(1, p - 1))}
                        disabled={page === 1}
                        className="px-3 py-1.5 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50"
                      >
                        Previous
                      </button>
                      <button
                        onClick={() => setPage((p) => Math.min(reportsData.pages, p + 1))}
                        disabled={page === reportsData.pages}
                        className="px-3 py-1.5 text-sm border border-slate-300 dark:border-slate-600 rounded-lg disabled:opacity-50"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="p-12 text-center">
                <DocumentTextIcon className="h-12 w-12 mx-auto text-slate-500 dark:text-slate-400" />
                <p className="mt-3 text-sm font-medium text-slate-900 dark:text-white">No reports found</p>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                  Generate your first report to get started
                </p>
                <button
                  onClick={() => setActiveTab('generate')}
                  className="mt-4 btn btn-primary"
                >
                  Generate Report
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Scheduled Reports Tab */}
      {activeTab === 'scheduled' && (
        <ScheduledReportsTab templates={REPORT_TEMPLATES} />
      )}

      {/* Preview Modal */}
      {showPreview && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setShowPreview(false)} />
            <div className="relative bg-white dark:bg-slate-900 rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="sticky top-0 z-10 flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900">
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Report Preview</h3>
                <button onClick={() => setShowPreview(false)}>
                  <XMarkIcon className="h-6 w-6 text-slate-500 dark:text-slate-400 hover:text-slate-500" />
                </button>
              </div>
              <div className="p-6">
                <ReportPreview
                  template={selectedTemplate}
                  dateRange={{ start: formData.start_date, end: formData.end_date }}
                />
              </div>
              <div className="sticky bottom-0 flex items-center justify-end gap-3 p-4 border-t border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900">
                <button onClick={() => setShowPreview(false)} className="btn btn-secondary">
                  Close
                </button>
                <button
                  onClick={() => {
                    setShowPreview(false);
                    generateMutation.mutate();
                  }}
                  className="btn btn-primary flex items-center gap-2"
                >
                  <PaperAirplaneIcon className="h-4 w-4" />
                  Generate Report
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ReportsPage;
