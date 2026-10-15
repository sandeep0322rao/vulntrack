'use strict';
document.addEventListener('DOMContentLoaded', () => {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.font.family = 'Segoe UI, Arial, sans-serif';
  Chart.defaults.font.size = 10;
  Chart.defaults.color = '#89977d';
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.plugins.legend.labels.boxWidth = 7;
  Chart.defaults.plugins.legend.labels.padding = 17;
  const palette = ['#b77666', '#d7a376', '#d8c57b', '#a6be7f', '#d1dbbf', '#a5b9b6'];
  const make = (id, type, horizontal = false) => {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    const data = JSON.parse(canvas.dataset.chart);
    const labels = Object.keys(data);
    const values = Object.values(data);
    const donut = type === 'doughnut';
    new Chart(canvas, {
      type,
      data: { labels, datasets: [{data: values, backgroundColor: id === 'status-chart' ? ['#bdcda6', '#d6c88c', '#aec4ca', '#769a69', '#bdacc4', '#dde3d2'] : palette,
        borderWidth: donut ? 4 : 0, borderColor: '#fff', borderRadius: donut ? 0 : 4, barPercentage: .48, maxBarThickness: 26}] },
      options: {
        responsive: true, maintainAspectRatio: false,
        animation: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? false : { duration: 500 },
        indexAxis: horizontal ? 'y' : 'x', cutout: '75%',
        plugins: { legend: { display: donut, position: 'right', labels: {font: {size: 10}} }, tooltip: {backgroundColor: '#294e35', padding: 11},
          title: {display: false} },
        ...(donut ? {} : {scales: {x: {grid: {display: horizontal, color: '#f0f3eb'}, border: {display: false}, ticks: {font: {size: 9}, precision: 0}},
          y: {beginAtZero: true, grid: {display: !horizontal, color: '#f0f3eb'}, border: {display: false}, ticks: {precision: 0, font: {size: 9}}}}})
      }
    });
  };
  make('status-chart', 'bar');
  make('severity-chart', 'doughnut');
  make('category-chart', 'bar', true);
  make('priority-chart', 'bar');
});
